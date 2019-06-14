/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:54 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.goterl.lazycode.lazysodium.utils;

import static java.util.Objects.requireNonNull;

import com.goterl.lazycode.lazysodium.Sodium;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.sun.jna.Native;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.ProviderNotFoundException;

/**
 * A simple library class which helps with loading dynamic sodium library stored in the
 * JAR archive. Works with JNA.
 *
 * <p>This class is thread-safe.
 *
 * @see <a href="http://adamheinrich.com/blog/2012/how-to-load-native-jni-library-from-jar">http://adamheinrich.com/blog/2012/how-to-load-native-jni-library-from-jar</a>
 * @see <a href="https://github.com/adamheinrich/native-utils">https://github.com/adamheinrich/native-utils</a>
 */
public final class LibraryLoader {

    private static LibraryLoader INSTANCE = new LibraryLoader(Native::register);

    private final JnaLoader loader;
    private final Object lock = new Object();

    /** True iff the library was successfully loaded; false — otherwise. */
    private boolean loaded;

    /**
     * Temporary directory which will contain the DLLs.
     * {@code null} unless {@link #loadLibraryFromJar(String)} was used to load the library.
     */
    private File temporaryDir;

    // VisibleForTesting
    LibraryLoader(JnaLoader loader) {
        this.loader = loader;
        this.loaded = false;
        this.temporaryDir = null;
    }

    /** Returns the global instance of the library loader. */
    public static LibraryLoader getInstance() {
        return INSTANCE;
    }

    /**
     * Loads library from the current JAR archive and registers the native methods
     * of {@link Sodium} and {@link SodiumJava}. The library will be loaded at most once.
     *
     * <p>The file from JAR is copied into system temporary directory and then loaded.
     * The temporary file is deleted after exiting.
     *
     * <p>Method uses String as filename because the pathname is "abstract", not system-dependent.
     *
     * @param pathInJar The path of file inside JAR as absolute path (beginning with '/'),
     *      e.g. /package/File.ext
     * @throws IOException If temporary file creation or read/write operation fails
     * @throws IllegalArgumentException If source file (param path) does not exist
     * @throws FileNotFoundException If the file could not be found inside the JAR.
     */
    public void loadLibraryFromJar(String pathInJar) throws IOException {
        requireNonNull(pathInJar, "pathInJar");
        synchronized (lock) {
            if (loaded) {
                return;
            }

            File sodiumLib = copyFromJarToTemp(pathInJar);
            loadLibrary(sodiumLib.getAbsolutePath());
            requestLibDeletion(sodiumLib);
        }
    }

    /**
     * Loads the sodium library and registers the native methods of {@link Sodium}
     * and {@link SodiumJava}.
     * The library will be loaded at most once.
     *
     * @param libLocator a library locator: either a path to it, or, for installed libraries,
     *      a short name (sodium) or a full name (e.g., libsodium.dylib)
     * @see Native#register(Class, String)
     */
    public void loadLibrary(String libLocator) {
        requireNonNull(libLocator, "libLocator");
        synchronized (lock) {
            if (loaded) {
                return;
            }
            loader.register(Sodium.class, libLocator);
            loader.register(SodiumJava.class, libLocator);
            loaded = true;
        }
    }

    private File copyFromJarToTemp(String pathInJar) throws IOException {
        // Prepare temporary directory
        if (temporaryDir == null) {
            temporaryDir = createTempDirectory();
        }

        String fileName = new File(pathInJar).getName();
        File temp = new File(temporaryDir, fileName);
        InputStream is = LibraryLoader.class.getResourceAsStream(pathInJar);

        // This check falls back to loading the .so from editors like
        // IntelliJ and Eclipse
        // if (is == null) {
        //    is = LibraryLoader.class.getResourceAsStream(pathInJar);
        // }

        OutputStream out = new BufferedOutputStream(new FileOutputStream(temp, false));
        try {
            byte [] dest = new byte[4096];
            int amt = is.read(dest);
            while (amt != -1) {
                out.write(dest, 0, amt);
                amt = is.read(dest);
            }
        } catch (IOException e) {
            temp.delete();
            throw e;
        } catch (Exception e) {
            temp.delete();
            String message = String.format("Failed to copy the lib from JAR (%s) into %s",
                pathInJar, temp);
            throw new IOException(message, e);
        } finally {
            is.close();
            out.close();
        }

        return temp;
    }

    private void requestLibDeletion(File sodiumLib) {
        if (isPosixCompliant()) {
            // Assume POSIX compliant file system, the library can be deleted
            // immediately after loading
            sodiumLib.delete();
        } else {
            // Assume non-POSIX, and don't delete until last file descriptor closed
            sodiumLib.deleteOnExit();
        }
    }

    private static boolean isPosixCompliant() {
        try {
            return FileSystems.getDefault()
                    .supportedFileAttributeViews()
                    .contains("posix");
        } catch (FileSystemNotFoundException
                | ProviderNotFoundException
                | SecurityException e) {
            return false;
        }
    }

    // VisibleForTesting
    static File createTempDirectory() throws IOException {
        String tempDirPrefix = "lazysodium";
        File generatedDir = Files.createTempDirectory(tempDirPrefix)
            .toFile();

        generatedDir.deleteOnExit();
        return generatedDir;
    }

    /**
     * A JNA loader, loading the library (if needed) and registering the class native
     * methods.
     *
     * <p>This interface exists to enable unit testing of library loading in a single
     * process — a thing that can only happen once.
     */
    interface JnaLoader {
        void register(Class<?> type, String libLocator);
    }
}
