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
import com.sun.jna.Platform;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.ProviderNotFoundException;
import java.nio.file.attribute.PosixFilePermission;
import java.util.HashSet;
import java.util.Set;

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

    /**
     * Library loading mode controls which libraries are attempted to be loaded (installed in the system or bundled
     * in the Lazysodium JAR) and in which order.
     *
     * <p>It is also possible to load a custom build of sodium library from an arbitrary directory using
     * {@link LibraryLoader#loadLibrary(String)}
     */
    public enum Mode {

        /**
         * Try to load the system sodium first, if that fails — load the bundled version.
         *
         * <p>This is the recommended mode, because it allows the clients to upgrade the sodium library
         * as soon as it is available instead of waiting for lazysodium release and releasing a new version of
         * the client library/application.
         */
        PREFER_SYSTEM,

        /**
         * Load the bundled version, ignoring the system.
         *
         * <p>This mode might be useful if the system sodium turns out to be outdated and cannot be upgraded.
         */
        BUNDLED_ONLY,

        /**
         * Load the system sodium only, ignoring the bundled.
         *
         * <p>This mode is recommended if it is required to use the system sodium only, and the application
         * must fail if it is not installed.
         */
        SYSTEM_ONLY,
    }

    private static LibraryLoader INSTANCE = new LibraryLoader(Native::register);

    private final JnaLoader loader;
    private final Object lock = new Object();

    /** True iff the library was successfully loaded; false — otherwise. */
    private boolean loaded;

    /**
     * Temporary directory which will contain the DLLs.
     * {@code null} unless it was attempted to load the library from resources.
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
     * Loads the sodium library and registers the native methods of {@link Sodium}
     * and {@link SodiumJava} using the specified loading mode.
     * The library will be loaded at most once.
     *
     * @param mode controls which sodium library (installed in the system or bundled in the JAR)
     *     is loaded, and in which order
     * @throws LibraryLoadingException if fails to load the library
     * @see Native#register(Class, String)
     */
    public void loadLibrary(Mode mode) {
        synchronized (lock) {
            switch (mode) {
                case PREFER_SYSTEM:
                    try {
                        loadSystemLibrary();
                    } catch (LibraryLoadingException suppressed) {
                        // Attempt to load the bundled
                        loadBundledLibrary();
                    }
                    break;
                case BUNDLED_ONLY:
                    loadBundledLibrary();
                    break;
                case SYSTEM_ONLY:
                    loadSystemLibrary();
                    break;
                default:
                    throw new IllegalStateException("Unsupported mode: " + mode);
            }
        }
    }

    private void loadSystemLibrary() {
        loadLibrary("sodium");
    }

    /**
     * Loads library from the current JAR archive and registers the native methods
     * of {@link Sodium} and {@link SodiumJava}. The library will be loaded at most once.
     *
     * <p>The file from JAR is copied into system temporary directory and then loaded.
     * The temporary file is deleted after exiting.
     *
     * @throws LibraryLoadingException If fails to load the library
     */
    private void loadBundledLibrary() {
        if (loaded) {
            return;
        }

        String pathInJar = getSodiumPathInResources();
        try {
            File sodiumLib = copyFromJarToTemp(pathInJar);
            loadLibrary(sodiumLib.getAbsolutePath());
            requestLibDeletion(sodiumLib);
        } catch (IOException e) {
            String message = String.format("Failed to load the bundled library from resources by path (%s)",
                    pathInJar);
            throw new LibraryLoadingException(message, e);
        }
    }

    /**
     * Loads the sodium library and registers the native methods of {@link Sodium}
     * and {@link SodiumJava}.
     * The library will be loaded at most once.
     *
     * @param libLocator a library locator: either a path to it, or, for installed libraries,
     *      a short name (sodium) or a full name (e.g., libsodium.dylib)
     * @throws LibraryLoadingException if fails to load the library
     * @see Native#register(Class, String)
     */
    public void loadLibrary(String libLocator) {
        requireNonNull(libLocator, "libLocator");
        synchronized (lock) {
            if (loaded) {
                return;
            }
            try {
                loader.register(Sodium.class, libLocator);
                loader.register(SodiumJava.class, libLocator);
                loaded = true;
            } catch (UnsatisfiedLinkError e) {
                // Translate UnsatisfiedLinkError which JNA throws if it fails to find the library using the supplied
                // locator into LibraryLoadingException.
                throw new LibraryLoadingException("Failed to load the library using " + libLocator, e);
            }
        }
    }

    /**
     * Returns the absolute path to sodium library inside JAR (beginning with '/'), e.g. /linux/libsodium.so.
     */
    private static String getSodiumPathInResources() {
        return getPath("armv6", "libsodium.so");
    }

    private static String getPath(String folder, String name) {
        String separator = "/";
        String resourcePath = folder + separator + name;
        if (!resourcePath.startsWith(separator)) {
            resourcePath = separator + resourcePath;
        }
        return resourcePath;
    }

    private File copyFromJarToTemp(String pathInJar) throws IOException {
        // Prepare temporary directory
        if (temporaryDir == null) {
            temporaryDir = createTempDirectory();
        }

        String fileName = new File(pathInJar).getName();
        File temp = new File(temporaryDir, fileName);
        temp.delete();
        temp.createNewFile();

        InputStream is = LibraryLoader.class.getResourceAsStream(pathInJar);
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
        setPermissions(temp);
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
    static File createTempDirectory() {
        String tempDir = System.getProperty("user.home");
        File hydrideDirectory = new File(tempDir, "lazysodium");
        hydrideDirectory.mkdir();
        hydrideDirectory.deleteOnExit();
        return hydrideDirectory;
    }

    private void setPermissions(File file) throws IOException{
        if (isPosixCompliant()) {
            Set<PosixFilePermission> perms = new HashSet<>();
            perms.add(PosixFilePermission.OWNER_READ);
            perms.add(PosixFilePermission.OWNER_WRITE);
            perms.add(PosixFilePermission.OWNER_EXECUTE);

            perms.add(PosixFilePermission.OTHERS_READ);
            perms.add(PosixFilePermission.OTHERS_WRITE);
            perms.add(PosixFilePermission.OTHERS_EXECUTE);

            perms.add(PosixFilePermission.GROUP_READ);
            perms.add(PosixFilePermission.GROUP_WRITE);
            perms.add(PosixFilePermission.GROUP_EXECUTE);
            Files.setPosixFilePermissions(file.toPath(), perms);
        } else {
            file.setWritable(true);
            file.setReadable(true);
            file.setExecutable(true);
        }
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
