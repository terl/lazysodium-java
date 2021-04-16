/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.utils.DetachedDecrypt;
import com.goterl.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazysodium.utils.Key;
import com.sun.jna.Structure;

import javax.crypto.AEADBadTagException;
import java.util.Arrays;
import java.util.List;

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


    // AES256

    int AES256GCM_KEYBYTES = 32;
    int AES256GCM_NSECBYTES = 0;
    int AES256GCM_NPUBBYTES = 12;
    int AES256GCM_ABYTES = 16;



    enum Method {
        CHACHA20_POLY1305,
        CHACHA20_POLY1305_IETF,
        XCHACHA20_POLY1305_IETF,
        AES256GCM,
    }



    interface Native {

        void cryptoAeadChaCha20Poly1305Keygen(byte[] key);

        boolean cryptoAeadChaCha20Poly1305Encrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305Decrypt(
                byte[] message,
                long[] messageLen,
                byte[] nSec,
                byte[] cipher,
                long cipherLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305EncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305DecryptDetached(
                byte[] message,
                byte[] nSec,
                byte[] cipher,
                long cipherLen,
                byte[] mac,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nPub,
                byte[] key
        );




        // ietf

        void cryptoAeadChaCha20Poly1305IetfKeygen(byte[] key);

        boolean cryptoAeadChaCha20Poly1305IetfEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305IetfDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] nSec,
                byte[] cipher,
                long cipherLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305IetfEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadChaCha20Poly1305IetfDecryptDetached(
                byte[] message,
                byte[] nSec,
                byte[] cipher,
                long cipherLen,
                byte[] mac,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nPub,
                byte[] key
        );




        // xchacha

        void cryptoAeadXChaCha20Poly1305IetfKeygen(byte[] key);

        boolean cryptoAeadXChaCha20Poly1305IetfEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadXChaCha20Poly1305IetfDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] nSec,
                byte[] cipher,
                long cipherLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nPub,
                byte[] key
        );


        boolean cryptoAeadXChaCha20Poly1305IetfEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadXChaCha20Poly1305IetfDecryptDetached(
                byte[] message,
                byte[] nSec,
                byte[] cipher,
                long cipherLen,
                byte[] mac,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nPub,
                byte[] key
        );


        // AES

        void cryptoAeadAES256GCMKeygen(byte[] key);

        boolean cryptoAeadAES256GCMEncrypt(
                byte[] cipher,
                long[] cipherLen,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadAES256GCMDecrypt(
                byte[] message,
                long[] messageLen,
                byte[] nSec,
                byte[] cipher,
                long cipherLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nPub,
                byte[] key
        );


        boolean cryptoAeadAES256GCMEncryptDetached(
                byte[] cipher,
                byte[] mac,
                long[] macLenAddress,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nSec,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadAES256GCMDecryptDetached(
                byte[] message,
                byte[] nSec,
                byte[] cipher,
                long cipherLen,
                byte[] mac,
                byte[] additionalData,
                long additionalDataLen,
                byte[] nPub,
                byte[] key
        );

        boolean cryptoAeadAES256GCMIsAvailable();

    }



    interface Lazy {

        Key keygen(Method method);

        String encrypt(String m,
                      String additionalData,
                      byte[] nPub,
                      Key k,
                      AEAD.Method method);

        String encrypt(
                String m,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                Key k,
                Method method
        );

        String decrypt(
                String cipher,
                String additionalData,
                byte[] nPub,
                Key k,
                AEAD.Method method
        ) throws AEADBadTagException;

        String decrypt(
                String cipher,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                Key k,
                Method method
        ) throws AEADBadTagException;

        DetachedEncrypt encryptDetached(
                String m,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                Key k,
                Method method
        );

        DetachedDecrypt decryptDetached(
                DetachedEncrypt detachedEncrypt,
                String additionalData,
                byte[] nSec,
                byte[] nPub,
                Key k,
                Method method
        ) throws AEADBadTagException;


    }



    class StateAES extends Structure {

        public static class ByReference extends StateAES implements Structure.ByReference {

        }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("arr");
        }

        public byte[] arr = new byte[512];

    }


}
