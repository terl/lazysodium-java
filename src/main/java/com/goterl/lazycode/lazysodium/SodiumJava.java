/*
 * Copyright (c) Terl Tech Ltd • 23/05/18 17:02 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.goterl.lazycode.lazysodium.utils.NativeUtils;
import com.sun.jna.Native;
import com.sun.jna.Platform;

import java.io.File;
import java.io.IOException;

public class SodiumJava extends Sodium {

    public SodiumJava() {
        registerFromResources();
    }


    /**
     * Please note that the libsodium.so
     * file HAS to be built for the platform this program will run on.
     *
     * @param path Absolute path to libsodium.so.
     */
    public SodiumJava(String path) {
        Native.register(SodiumJava.class, path);
    }



    public native int crypto_pwhash_scryptsalsa208sha256(
            byte[] out,
            long outLen,
            byte[] password,
            long passwordLen,
            byte[] salt,
            long opsLimit,
            long memLimit
    );

    public native int crypto_pwhash_scryptsalsa208sha256_str(
            byte[] out,
            byte[] password,
            long passwordLen,
            long opsLimit,
            long memLimit
    );

    public native int crypto_pwhash_scryptsalsa208sha256_str_verify(
            byte[] str,
            byte[] password,
            long passwordLen
    );

    public native int crypto_pwhash_scryptsalsa208sha256_ll(
            byte[] password,
            int passwordLen,
            byte[] salt,
            int saltLen,
            long N,
            long r,
            long p,
            byte[] buf,
            int bufLen
    );

    public native int crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(
            byte[] password,
            long opsLimit,
            long memLimit
    );





    private void registerFromResources() {
        String path = getLibSodiumFromResources();
        try {
            NativeUtils.loadLibraryFromJar(path);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getLibSodiumFromResources() {
        String path = getPath("windows", "libsodium.dll");
        if (Platform.isLinux() || Platform.isAndroid()) {
            path = getPath("linux", "libsodium.so");
        } else if (Platform.isMac()) {
            path = getPath("mac", "libsodium.dylib");
        }
        return path;
    }

    private String getPath(String folder, String name) {
        String resourcePath = folder + File.separator + name;
        if (!resourcePath.startsWith(File.separator)) {
            resourcePath = File.separator + resourcePath;
        }
        return resourcePath;
    }


}
