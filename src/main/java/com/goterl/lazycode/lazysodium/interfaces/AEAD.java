/*
 * Copyright (c) Terl Tech Ltd • 07/05/18 13:07 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.utils.DetachedDecrypt;
import com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;

public interface AEAD {


    // REGULAR CHACHA

    int CHACHA20POLY1305_KEYBYTES = 32,
        CHACHA20POLY1305_NPUBBYTES = 8,
        CHACHA20POLY1305_ABYTES = 16;



    // IETF CHACHA

    int CHACHA20POLY1305_IETF_ABYTES = 16,
        CHACHA20POLY1305_IETF_KEYBYTES = 32,
        CHACHA20POLY1305_IETF_NPUBBYTES = 12;



    // This is XCHACHA not CHACHA.

    int XCHACHA20POLY1305_IETF_KEYBYTES = 32,
        XCHACHA20POLY1305_IETF_ABYTES = 16,
        XCHACHA20POLY1305_IETF_NPUBBYTES = 24;


    enum Method {
        CHACHA20_POLY1305,
        CHACHA20_POLY1305_IETF,
        XCHACHA20_POLY1305_IETF,
    }



    interface Native {

        void cryptoAeadChaCha20Poly1305Keygen(byte[] key);

        boolean cryptoAeadChaCha20Poly1305Encrypt(
                byte[] c,
                long cLen,
                byte[] m,
                long mLen,
                byte[] ad,
                long adLen,
                byte[] nSec,
                byte[] nPub,
                byte[] k
        );

        boolean cryptoAeadChaCha20Poly1305Decrypt(
                byte[] m,
                long mLen,
                byte[] nSec,
                byte[] c,
                long cLen,
                byte[] ad,
                long adLen,
                byte[] nPub,
                byte[] k
        );

        boolean cryptoAeadChaCha20Poly1305EncryptDetached(
                byte[] c,
                byte[] mac,
                Long macLenAddress,
                byte[] m,
                long mLen,
                byte[] ad,
                long adLen,
                byte[] nSec,
                byte[] nPub,
                byte[] k
        );

        boolean cryptoAeadChaCha20Poly1305DecryptDetached(
                byte[] m,
                byte[] nSec,
                byte[] c,
                long cLen,
                byte[] mac,
                byte[] ad,
                long adLen,
                byte[] nPub,
                byte[] k
        );




        // ietf

        void cryptoAeadChaCha20Poly1305IetfKeygen(byte[] key);

        boolean cryptoAeadChaCha20Poly1305IetfEncrypt(
                byte[] c,
                long cLen,
                byte[] m,
                long mLen,
                byte[] ad,
                long adLen,
                byte[] nSec,
                byte[] nPub,
                byte[] k
        );

        boolean cryptoAeadChaCha20Poly1305IetfDecrypt(
                byte[] m,
                long mLen,
                byte[] nSec,
                byte[] c,
                long cLen,
                byte[] ad,
                long adLen,
                byte[] nPub,
                byte[] k
        );

        boolean cryptoAeadChaCha20Poly1305IetfEncryptDetached(
                byte[] c,
                byte[] mac,
                Long macLenAddress,
                byte[] m,
                long mLen,
                byte[] ad,
                long adLen,
                byte[] nSec,
                byte[] nPub,
                byte[] k
        );

        boolean cryptoAeadChaCha20Poly1305IetfDecryptDetached(
                byte[] m,
                byte[] nSec,
                byte[] c,
                long cLen,
                byte[] mac,
                byte[] ad,
                long adLen,
                byte[] nPub,
                byte[] k
        );




        // xchacha

        void cryptoAeadXChaCha20Poly1305IetfKeygen(byte[] k);

        boolean cryptoAeadXChaCha20Poly1305IetfEncrypt(
                byte[] c,
                long cLen,
                byte[] m,
                long mLen,
                byte[] ad,
                long adLen,
                byte[] nSec,
                byte[] nPub,
                byte[] k
        );

        boolean cryptoAeadXChaCha20Poly1305IetfDecrypt(
                byte[] m,
                long mLen,
                byte[] nSec,
                byte[] c,
                long cLen,
                byte[] ad,
                long adLen,
                byte[] nPub,
                byte[] k
        );


        boolean cryptoAeadXChaCha20Poly1305IetfEncryptDetached(
                byte[] c,
                byte[] mac,
                Long macLenAddress,
                byte[] m,
                long mLen,
                byte[] ad,
                long adLen,
                byte[] nSec,
                byte[] nPub,
                byte[] k
        );

        boolean cryptoAeadXChaCha20Poly1305IetfDecryptDetached(
                byte[] m,
                byte[] nSec,
                byte[] c,
                long cLen,
                byte[] mac,
                byte[] ad,
                long adLen,
                byte[] nPub,
                byte[] k
        );

    }



    interface Lazy {

        String keygen(Method method);

        String encrypt(
                String m,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                String k,
                Method method
        );

        String decrypt(
                String cipher,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                String k,
                Method method
        );

        DetachedEncrypt encryptDetached(
                String m,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                String k,
                Method method
        );

        DetachedDecrypt decryptDetached(
                String cipher,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                String k,
                Method method
        );


    }




}
