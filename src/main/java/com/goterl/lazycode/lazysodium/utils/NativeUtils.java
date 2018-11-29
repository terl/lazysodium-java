/*
 * Copyright (c) Terl Tech Ltd • 16/05/18 11:39 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */
package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.Sodium;
import com.goterl.lazycode.lazysodium.SodiumJava;
import com.sun.jna.Native;

import java.io.*;
import java.nio.file.*;

/**
 * A simple library class which helps with loading dynamic libraries stored in the
 * JAR archive. These libraries usually contain implementation of some methods in
 * native code (using JNI - Java Native Interface).
 *
 * @see <a href="http://adamheinrich.com/blog/2012/how-to-load-native-jni-library-from-jar">http://adamheinrich.com/blog/2012/how-to-load-native-jni-library-from-jar</a>
 * @see <a href="https://github.com/adamheinrich/native-utils">https://github.com/adamheinrich/native-utils</a>
 *
 */
public class NativeUtils {

    /**
     * The minimum length a prefix for a file has to have according to {@link File#createTempFile(String, String)}}.
     */
    private static final int MIN_PREFIX_LENGTH = 3;

    /**
     * Temporary directory which will contain the DLLs.
     */
    private static File temporaryDir;

    /**
     * Private constructor - this class will never be instanced
     */
    private NativeUtils() {
    }

    /**
     * Loads library from current JAR archive
     *
     * The file from JAR is copied into system temporary directory and then loaded. The temporary file is deleted after
     * exiting.
     * Method uses String as filename because the pathname is "abstract", not system-dependent.
     *
     * @param path The path of file inside JAR as absolute path (beginning with '/'), e.g. /package/File.ext
     * @throws IOException If temporary file creation or read/write operation fails
     * @throws IllegalArgumentException If source file (param path) does not exist
     * @throws IllegalArgumentException If the path is not absolute or if the filename is shorter than three characters
     * (restriction of {@link File#createTempFile(java.lang.String, java.lang.String)}).
     * @throws FileNotFoundException If the file could not be found inside the JAR.
     */
    public static void loadLibraryFromJar(String path) throws IOException {

        if (path == null) {
            throw new IOException("Path cannot be null.");
        }

        String fileName = new File(path).getName();
        if (fileName.length() <= MIN_PREFIX_LENGTH) {
            throw new IOException(
                    "The filename of your native library (" + fileName +
                    ") should be of length longer than " + MIN_PREFIX_LENGTH +
                    " characters."
            );
        }

        // Prepare temporary file
        if (temporaryDir == null) {
            temporaryDir = createTempDirectory();
            temporaryDir.deleteOnExit();
        }

        File temp = new File(temporaryDir, fileName);
        InputStream is = NativeUtils.class.getResourceAsStream(path);

        // This check falls back to loading the .so from editors like
        // IntelliJ and Eclipse
        if (is == null) {
            is = NativeUtils.class.getResourceAsStream(path);
        }

        FileOutputStream out = new FileOutputStream(temp, false);
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
        } catch (NullPointerException e) {
            temp.delete();
            throw new FileNotFoundException("File " + path + " was not found inside JAR.");
        } finally {
            is.close();
            out.close();
        }

        // Modified to work with JNA
        try {
            Native.register(Sodium.class, temp.getAbsolutePath());
            Native.register(SodiumJava.class, temp.getAbsolutePath());
        } finally {
            if (isPosixCompliant()) {
                // Assume POSIX compliant file system, can be deleted after loading
                temp.delete();
            } else {
                // Assume non-POSIX, and don't delete until last file descriptor closed
                temp.deleteOnExit();
            }
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

    private static File createTempDirectory() throws IOException {
        String tempDir = System.getProperty("java.io.tmpdir");
        File generatedDir = new File(tempDir, "libsodium");

        if (generatedDir.exists()) {
            generatedDir.delete();
        }

        if (!generatedDir.mkdirs()) {
            throw new IOException("Failed to create temp directory " + generatedDir.getAbsolutePath());
        }

        return generatedDir;
    }
}
