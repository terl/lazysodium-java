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
        onRegistered();
    }


    /**
     * Please note that the libsodium.so
     * file HAS to be built for the platform this program will run on.
     *
     * @param path Absolute path to libsodium.so.
     */
    public SodiumJava(String path) {
        Native.register(SodiumJava.class, path);
        onRegistered();
    }


    // Scrypt


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


    // Salsa20 12 rounds

    public native void crypto_stream_salsa2012_keygen(byte[] key);

    public native int crypto_stream_salsa2012(
            byte[] c,
            long cLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_salsa2012_xor(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );


    public native void crypto_stream_salsa208_keygen(byte[] key);

    public native int crypto_stream_salsa208(
            byte[] c,
            long cLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_salsa208_xor(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );


    // XChaCha20

    public native int crypto_stream_xchacha20(
            byte[] c,
            long cLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_xchacha20_xor(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            byte[] key
    );

    public native int crypto_stream_xchacha20_xor_ic(
            byte[] cipher,
            byte[] message,
            long messageLen,
            byte[] nonce,
            long ic,
            byte[] key
    );

    public native void crypto_stream_xchacha20_keygen(byte[] key);




    private void registerFromResources() {
        String path = getLibSodiumFromResources();
        try {
            NativeUtils.loadLibraryFromJar(path);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String getLibSodiumFromResources() {
        String path = "";

        boolean is64Bit = com.sun.jna.Native.POINTER_SIZE == 8;

        System.out.println("Is 64bit:" + is64Bit);
        if (Platform.isWindows()) {
            if (is64Bit) {
                path = getPath("windows64", "libsodium.dll");
            } else {
                path = getPath("windows", "libsodium.dll");
            }
        }
        if (Platform.isLinux()) {
            System.out.println("Is linux");
            if (is64Bit) {
                path = getPath("linux64", "libsodium.so");
            } else {
                path = getPath("linux64", "libsodium.so");
            }
        } else if (Platform.isMac()) {
            path = getPath("mac", "libsodium.dylib");
        }

        return path;
    }

    private String getPath(String folder, String name) {
        String separator = "/";
        String resourcePath = folder + separator + name;
        if (!resourcePath.startsWith(separator)) {
            resourcePath = separator + resourcePath;
        }
        return resourcePath;
    }


}
