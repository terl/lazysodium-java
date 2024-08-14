/*
 * Copyright (c) Terl Tech Ltd  • 04/04/2021, 00:07 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.codevasp.lazysodium.utils;


import com.sun.jna.Platform;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.*;
import java.util.jar.JarFile;
import java.util.jar.Manifest;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


/**
 * Loads resources from a relative or absolute path
 * even if the file is in a JAR.
 */
public class ResourceLoader {

    private static final long FILE_COPY_BUFFER_SIZE = 1000000 * 30;
    private final Logger logger = LoggerFactory.getLogger("ResourceLoader");
    private final Collection<PosixFilePermission> writePerms = new ArrayList<>();
    private final Collection<PosixFilePermission> readPerms = new ArrayList<>();
    private final Collection<PosixFilePermission> execPerms = new ArrayList<>();

    ResourceLoader() {
        readPerms.add(PosixFilePermission.OWNER_READ);
        readPerms.add(PosixFilePermission.OTHERS_READ);
        readPerms.add(PosixFilePermission.GROUP_READ);

        writePerms.add(PosixFilePermission.OWNER_WRITE);
        writePerms.add(PosixFilePermission.OTHERS_WRITE);
        writePerms.add(PosixFilePermission.GROUP_WRITE);

        execPerms.add(PosixFilePermission.OWNER_EXECUTE);
        execPerms.add(PosixFilePermission.OTHERS_EXECUTE);
        execPerms.add(PosixFilePermission.GROUP_EXECUTE);
    }

    /**
     * From https://www.javadevjournal.com/java/zipping-and-unzipping-in-java/
     *
     * @param zipFilePath   An absolute path to a zip file
     * @param unzipLocation Where to unzip the zip file
     * @throws IOException If could not unzip.
     */
    private static void unzip(final String zipFilePath, final String unzipLocation) throws IOException {
        if (!(Files.exists(Paths.get(unzipLocation)))) {
            Files.createDirectories(Paths.get(unzipLocation));
        }
        try (ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry = zipInputStream.getNextEntry();
            while (entry != null) {
                Path filePath = Paths.get(unzipLocation, entry.getName());
                if (!entry.isDirectory()) {
                    filePath.getParent().toFile().mkdirs();
                    unzipFiles(zipInputStream, filePath);
                } else {
                    Files.createDirectories(filePath);
                }

                zipInputStream.closeEntry();
                entry = zipInputStream.getNextEntry();
            }
        }
    }

    private static void unzipFiles(final ZipInputStream zipInputStream, final Path unzipFilePath) throws IOException {
        try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(unzipFilePath.toAbsolutePath().toString()))) {
            byte[] bytesIn = new byte[1024];
            int read = 0;
            while ((read = zipInputStream.read(bytesIn)) != -1) {
                bos.write(bytesIn, 0, read);
            }
        }
    }

    /**
     * From Apache Commons
     *
     * @param srcFile  The source file
     * @param destFile The destination file
     * @throws IOException
     */
    private static void doCopyFile(final File srcFile, final File destFile)
            throws IOException {
        if (destFile.exists() && destFile.isDirectory()) {
            throw new IOException("Destination '" + destFile + "' exists but is a directory");
        }

        try (FileInputStream fis = new FileInputStream(srcFile);
             FileChannel input = fis.getChannel();
             FileOutputStream fos = new FileOutputStream(destFile);
             FileChannel output = fos.getChannel()) {
            final long size = input.size(); // TODO See IO-386
            long pos = 0;
            long count = 0;
            while (pos < size) {
                final long remain = size - pos;
                count = remain > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : remain;
                final long bytesCopied = output.transferFrom(input, pos, count);
                if (bytesCopied == 0) { // IO-385 - can happen if file is truncated after caching the size
                    break; // ensure we don't loop forever
                }
                pos += bytesCopied;
            }
        }

        final long srcLen = srcFile.length(); // TODO See IO-386
        final long dstLen = destFile.length(); // TODO See IO-386
        if (srcLen != dstLen) {
            throw new IOException("Failed to copy full contents from '" +
                    srcFile + "' to '" + destFile + "' Expected length: " + srcLen + " Actual: " + dstLen);
        }
    }

    /**
     * From Apache Commons
     *
     * @param srcDir  The source directory
     * @param destDir The destination directory
     * @throws IOException
     */
    private static void copyDirectory(final File srcDir, final File destDir) throws IOException {
        if (srcDir.getCanonicalPath().equals(destDir.getCanonicalPath())) {
            throw new IOException("Source '" + srcDir + "' and destination '" + destDir + "' are the same");
        }

        // Cater for destination being directory within the source directory (see IO-141)
        List<String> exclusionList = null;
        if (destDir.getCanonicalPath().startsWith(srcDir.getCanonicalPath())) {
            final File[] srcFiles = srcDir.listFiles();
            if (srcFiles != null && srcFiles.length > 0) {
                exclusionList = new ArrayList<>(srcFiles.length);
                for (final File srcFile : srcFiles) {
                    final File copiedFile = new File(destDir, srcFile.getName());
                    exclusionList.add(copiedFile.getCanonicalPath());
                }
            }
        }
        doCopyDirectory(srcDir, destDir, exclusionList);
    }

    private static void doCopyDirectory(final File srcDir, final File destDir, final List<String> exclusionList)
            throws IOException {
        // recurse
        final File[] srcFiles = srcDir.listFiles();
        if (srcFiles == null) {  // null if abstract pathname does not denote a directory, or if an I/O error occurs
            throw new IOException("Failed to list contents of " + srcDir);
        }
        if (destDir.exists()) {
            if (destDir.isDirectory() == false) {
                throw new IOException("Destination '" + destDir + "' exists but is not a directory");
            }
        } else {
            if (!destDir.mkdirs() && !destDir.isDirectory()) {
                throw new IOException("Destination '" + destDir + "' directory cannot be created");
            }
        }
        if (destDir.canWrite() == false) {
            throw new IOException("Destination '" + destDir + "' cannot be written to");
        }
        for (final File srcFile : srcFiles) {
            final File dstFile = new File(destDir, srcFile.getName());
            if (exclusionList == null || !exclusionList.contains(srcFile.getCanonicalPath())) {
                if (srcFile.isDirectory()) {
                    doCopyDirectory(srcFile, dstFile, exclusionList);
                } else {
                    doCopyFile(srcFile, dstFile);
                }
            }
        }
    }

    /**
     * Creates the main temporary directory for resource-loader.
     *
     * @return A directory that you can store temporary resources in
     * @throws IOException Could not create a temporary directory
     */
    public static File createMainTempDirectory() throws IOException {
        Path path = Files.createTempDirectory("resource-loader");
        File dir = path.toFile();
        dir.mkdir();
        dir.deleteOnExit();
        return dir;
    }

    /**
     * Gets the base location of the given class.
     * From SciJava class.
     * <p>
     * If the class is directly on the file system (e.g.,
     * "/path/to/my/package/MyClass.class") then it will return the base directory
     * (e.g., "file:/path/to").
     * </p>
     * <p>
     * If the class is within a JAR file (e.g.,
     * "/path/to/my-jar.jar!/my/package/MyClass.class") then it will return the
     * path to the JAR (e.g., "file:/path/to/my-jar.jar").
     * </p>
     *
     * @param c The class whose location is desired.
     */
    public static URL getThePathToTheJarWeAreIn(final Class<?> c) {
        if (c == null) return null; // could not load the class

        // Try the easy way first
        try {
            final URL codeSourceLocation =
                    c.getProtectionDomain().getCodeSource().getLocation();
            if (codeSourceLocation != null) {
                return getPathToTheNestedJar(codeSourceLocation.toString());
            }
        } catch (final SecurityException e) {
            // Cannot access protection domain.
        } catch (final NullPointerException e) {
            // Protection domain or code source is null.
        }

        // The easy way failed, so we try the hard way. We ask for the class
        // itself as a resource, then strip the class's path from the URL string,
        // leaving the base path.

        // Get the class' raw resource path
        // Should provide something like: jar:file:/C:/app.jar!/lazysodium.jar/com/some/package/Sodium.class
        final URL classResource = c.getResource(c.getSimpleName() + ".class");
        if (classResource == null) {
            return null; // cannot find class resource
        }

        // This line should provide something like
        // jar:file:/C:/app.jar!/lazysodium.jar/com/some/package/Sodium.class
        final String url = classResource.toString();

        // This line will give us com/some/package/Sodium.class
        final String suffix = c.getCanonicalName().replace('.', '/') + ".class";
        if (!url.endsWith(suffix)) {
            return null; // weird URL
        }

        // Strip the class's path from the URL string
        // This will now give us jar:file:/C:/app.jar!/lazysodium.jar/
        String path = url.substring(0, url.length() - suffix.length());

        return getPathToTheNestedJar(path);
    }

    /**
     * Converts the given {@link URL} to its corresponding {@link File}.
     * From SciJava class.
     * <p>
     * This method is similar to calling {@code new File(url.toURI())} except that
     * it also handles "jar:file:" URLs, returning the path to the JAR file.
     * </p>
     *
     * @param url The URL to convert.
     * @return A file path suitable for use with e.g. {@link FileInputStream}
     * @throws IllegalArgumentException if the URL does not correspond to a file.
     */
    public static File urlToFile(final URL url) {
        return url == null ? null : urlToFile(url.toString());
    }

    /**
     * Converts the given URL string to its corresponding {@link File}.
     * From SciJava class.
     *
     * @param url The URL to convert.
     * @return A file path suitable for use with e.g. {@link FileInputStream}
     * @throws IllegalArgumentException if the URL does not correspond to a file.
     */
    public static File urlToFile(final String url) {
        String path = url;
        if (path.startsWith("jar:")) {
            // remove "jar:" prefix and "!/" suffix
            final int index = path.indexOf("!/");
            path = path.substring(4, index);
        }
        try {
            if (Platform.isWindows() && path.matches("file:[A-Za-z]:.*")) {
                path = "file:/" + path.substring(5);
            }
            return new File(new URL(path).toURI());
        } catch (final MalformedURLException e) {
            // NB: URL is not completely well-formed.
        } catch (final URISyntaxException e) {
            // NB: URL is not completely well-formed.
        }
        if (path.startsWith("file:")) {
            // pass through the URL as-is, minus "file:" prefix
            path = path.substring(5);
            return new File(path);
        }
        throw new IllegalArgumentException("Invalid URL: " + url);
    }

    /**
     * If the given URL is URL of jar, converts the given URL of jar to file URL
     *
     * @param url
     * @return
     */
    private static URL getPathToTheNestedJar(String url) {
        // Remove the "jar:" prefix
        if (url.startsWith("jar:")) {
            url = url.substring(4);
        }
        url = url.replaceAll("(\\.jar\\!)+", ".jar");
        // Remove all slashes from the end
        if (url.endsWith("/")) {
            url = url.replaceAll("\\/*$", "");
        }
        if (url.startsWith("nested:")) {
            // The nested syntax looks something like "nested:/app/appName.jar/!BOOT-INF/lib/lazysodium-java-5.1.4.jar"
            url = url.replace("nested:", "file:").replace("/!", "/");
        }
        try {
            // This should result in something like
            // file:/C:/app.jar/lazysodium.jar
            return new URL(url);
        } catch (MalformedURLException e) {
            return null;
        }
    }

    /**
     * Copies a file into a temporary directory regardless of
     * if it is in a JAR or not.
     *
     * @param relativePath A relative path to a file or directory
     *                     relative to the resources folder.
     * @return The file or directory you want to load.
     * @throws IOException        If at any point processing of the resource file fails.
     * @throws URISyntaxException If cannot find the resource file.
     */
    public File copyToTempDirectory(String relativePath, Class outsideClass) throws IOException, URISyntaxException {
        // Create a "main" temporary directory in which
        // everything can be thrown in.
        File mainTempDir = createMainTempDirectory();

        // Create the required directories.
        mainTempDir.mkdirs();

        // Is the user loading resources that are
        // from inside a JAR?
        URL fullJarPathURL = getThePathToTheJarWeAreIn(outsideClass);

        // Test if we are in a JAR and if we are
        // then do the following...
        if (isJarFile(fullJarPathURL)) {
            File extracted = extractFromWithinAJarFile(fullJarPathURL, mainTempDir, relativePath);
            if (extracted != null) {
                return extracted;
            }
        }

        // If not then get the file/directory
        // straight from the file system
        return getFileFromFileSystem(relativePath, mainTempDir);
    }

    public File extractFromWithinAJarFile(URL jarPath, File mainTempDir, String relativePath)
            throws IOException, URISyntaxException {
        if (jarPath == null) {
            return null;
        }
        // Split our JAR path
        String fullPath = jarPath + prefixStringWithSlashIfNotAlready(relativePath);
        return nestedExtract(mainTempDir, fullPath);
    }

    /**
     * If the string does not start with a slash, then
     * // make sure it does.
     *
     * @param s A string to prefix
     * @return A string with a slash prefixed
     */
    private String prefixStringWithSlashIfNotAlready(String s) {
        if (!s.startsWith("/")) {
            s = "/" + s;
        }
        return s;
    }

    /**
     * A method that keeps extracting JAR files from within each other.
     * This method only allows a maximum nested depth of 20.
     *
     * @param extractTo Where shall we initially extract files to.
     * @param fullPath  The full path to the initial
     * @return The final extracted file.
     * @throws IOException
     * @throws URISyntaxException
     */
    private File nestedExtract(File extractTo, String fullPath) throws IOException, URISyntaxException {
        final String JAR = ".jar";

        // After this line we have something like
        // file:C/app, some/lazysodium, file.txt
        String[] split = fullPath.split("(\\.jar/)");

        if (split.length > 20) {
            // What monster would put a JAR in a JAR 20 times?
            throw new StackOverflowError("We cannot extract a file 21 or more layers deep.");
        }

        // We have no ".jar/" so we go straight
        // to extraction.
        if (split.length == 1) {
            logger.debug("Extracted {} to {}", fullPath, extractTo.getAbsolutePath());
            return extractFilesOrFoldersFromJar(extractTo, new URL(fullPath), "");
        }

        String currentExtractionPath = "";
        File extracted = null;
        File nestedExtractTo = extractTo;
        for (int i = 0; i < split.length - 1; i++) {
            // Remember part = "file:C/app". But we need to know
            // where to extract these files. So we have
            // to prefix it with the current extraction path. We can't
            // just dump everything in the temp directory all the time.
            // Of course, we also suffix it with a ".jar". So at the end,
            // we get something like "file:C:/temp/app.jar"
            String part = currentExtractionPath + split[i] + JAR;
            // If we don't add this then when we pass it into
            // a URL() object then the URL object will complain
            if (!part.startsWith("file:")) {
                part = "file:" + part;
            }

            // Now, we need to "look ahead" and determine
            // the next part. We'd get something like
            // this: "/lazysodium".
            String nextPart = "/" + split[i + 1];

            // Now check if it's the last iteration of this for-loop.
            // If it isn't then add a ".jar" to nextPart, resulting
            // in something like "/lazysodium.jar"
            boolean isLastIteration = (i == (split.length - 2));
            if (!isLastIteration) {
                nextPart = nextPart + JAR;
            }

            // Now perform the extraction.
            logger.debug("Extracting {} from {}", nextPart, part);
            extracted = extractFilesOrFoldersFromJar(nestedExtractTo, new URL(part), nextPart);
            logger.debug("Extracted: {}", extracted.getAbsolutePath());

            // Note down the parent folder's location of the file we extracted to.
            // This will be used at the start of the for-loop as the
            // new destination to extract to.
            currentExtractionPath = nestedExtractTo.getAbsolutePath() + "/";
            nestedExtractTo = extracted.getParentFile();
        }
        return extracted;
    }

    /**
     * Does the URL lead to a valid JAR file? Usually
     * valid JAR files have a manifest.
     *
     * @param jarUrl
     * @return
     */
    private boolean isJarFile(URL jarUrl) {
        if (jarUrl != null) {
            String[] split = jarUrl.getPath().split("(\\.jar/)");
            String path;
            if (split.length == 1) {
                path = jarUrl.getPath();
            } else {
                path = split[0] + ".jar";
            }

            try (JarFile jarFile = new JarFile(path)) {
                // Successfully opened the jar file. Check if there's a manifest
                // This is probably not necessary
                Manifest manifest = jarFile.getManifest();
                if (manifest != null) {
                    return true;
                }
            } catch (IOException | IllegalStateException | SecurityException e) {
                logger.debug("This is not a JAR file due to {}", e.getMessage());
            }
        }
        return false;
    }

    /**
     * Extracts a file/directory from a JAR. A JAR is simply
     * a zip file. We can unzip it and get our file successfully.
     *
     * @param jarUrl    A JAR's URL.
     * @param outputDir A directory of where to store our extracted files.
     * @param pathInJar A relative path to a file that is in our resources folder.
     * @return The file or directory that we requested.
     * @throws URISyntaxException If we could not ascertain our location.
     * @throws IOException        If whilst unzipping we had some problems.
     */
    private File extractFilesOrFoldersFromJar(File outputDir, URL jarUrl, String pathInJar) throws URISyntaxException, IOException {
        File jar = urlToFile(jarUrl);
        unzip(jar.getAbsolutePath(), outputDir.getAbsolutePath());
        String filePath = outputDir.getAbsolutePath() + pathInJar;
        return new File(filePath);
    }

    /**
     * If we're not in a JAR then we can load directly from the file system
     * without all the unzipping fiasco present in {@see #getFileFromJar}.
     *
     * @param relativePath A relative path to a file or directory in the resources folder.
     * @param outputDir    A directory in which to store loaded files. Preferentially a temporary one.
     * @return The file or directory that was requested.
     * @throws IOException Could not find your requested file.
     */
    private File getFileFromFileSystem(String relativePath, File outputDir) throws IOException, URISyntaxException {
        relativePath = prefixStringWithSlashIfNotAlready(relativePath);
        final URL url = ResourceLoader.class.getResource(relativePath);
        final String urlString = url.getFile();
        final File file;
        if (Platform.isWindows()) {
            file = Paths.get(url.toURI()).toFile();
        } else {
            file = new File(urlString);
        }

        if (file.isFile()) {
            File resource = new File(relativePath);
            File resourceCopiedToTempFolder = new File(outputDir, resource.getName());
            doCopyFile(file, resourceCopiedToTempFolder);
            return resourceCopiedToTempFolder;
        } else {
            copyDirectory(file, outputDir);
            return outputDir;
        }
    }

    /**
     * Sets permissions on a file or directory. This allows all users
     * to read, write and execute.
     *
     * @param file A file to set global permissions on
     * @return The file with the global permissions set
     * @throws IOException Could not set permissions
     * @see #setPermissions(File, Set)
     */
    public File setPermissions(File file) throws IOException {
        return setPermissions(file, new HashSet<>());
    }

    /**
     * Sets a file or directory's permissions. @{code filePermissions} can be null, in that
     * case then global read, wrote and execute permissions will be set, so use
     * with caution.
     *
     * @param file            The file to set new permissions on.
     * @param filePermissions New permissions.
     * @return The file with correct permissions set.
     * @throws IOException
     */
    public File setPermissions(File file, Set<PosixFilePermission> filePermissions) throws IOException {
        if (isPosixCompliant()) {
            // For posix set fine grained permissions.
            if (filePermissions.isEmpty()) {
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
                filePermissions = perms;
            }
            Files.setPosixFilePermissions(file.toPath(), filePermissions);
        } else {
            // For non-posix like Windows find if any are true and
            // set the permissions accordingly.
            if (filePermissions.stream().anyMatch(readPerms::contains)) {
                file.setReadable(true);
            } else if (filePermissions.stream().anyMatch(writePerms::contains)) {
                file.setWritable(true);
            } else {
                file.setExecutable(true);
            }

        }
        return file;
    }

    /**
     * Mark the file or directory as "to be deleted".
     *
     * @param file The file or directory to be deleted.
     */
    public void requestDeletion(File file) {
        if (isPosixCompliant()) {
            // The file can be deleted immediately after loading
            file.delete();
        } else {
            // Don't delete until last file descriptor closed
            file.deleteOnExit();
        }
    }

    /**
     * Is the system we're running on Posix compliant?
     *
     * @return True if posix compliant.
     */
    protected boolean isPosixCompliant() {
        try {
            return FileSystems.getDefault()
                    .supportedFileAttributeViews()
                    .contains("posix");
        } catch (FileSystemNotFoundException | ProviderNotFoundException | SecurityException e) {
            return false;
        }
    }
}