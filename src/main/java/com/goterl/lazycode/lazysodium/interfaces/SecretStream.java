/*
 * Copyright (c) Terl Tech Ltd • 14/06/19 17:54 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.BaseChecker;
import com.goterl.lazycode.lazysodium.utils.Key;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public interface SecretStream {

    int CHACHA20_IETF_NONCEBYTES = 12;


    byte XCHACHA20POLY1305_TAG_PUSH = 0x01,
         XCHACHA20POLY1305_TAG_REKEY = 0x02,
         XCHACHA20POLY1305_TAG_MESSAGE = 0x00,
         XCHACHA20POLY1305_TAG_FINAL = XCHACHA20POLY1305_TAG_PUSH | XCHACHA20POLY1305_TAG_REKEY;

    byte TAG_PUSH = XCHACHA20POLY1305_TAG_PUSH,
         TAG_REKEY = XCHACHA20POLY1305_TAG_REKEY,
         TAG_MESSAGE = XCHACHA20POLY1305_TAG_MESSAGE,
         TAG_FINAL = XCHACHA20POLY1305_TAG_FINAL;

    int KEYBYTES = AEAD.XCHACHA20POLY1305_IETF_KEYBYTES,
        ABYTES = AEAD.XCHACHA20POLY1305_IETF_ABYTES + 1,
        HEADERBYTES = AEAD.XCHACHA20POLY1305_IETF_NPUBBYTES,
        NONCEBYTES = CHACHA20_IETF_NONCEBYTES;


    // 256GB
    long MESSAGEBYTES_MAX = 34359738368L;


    class Checker extends BaseChecker {

        public static void checkHeader(byte[] header) {
            checkEqual("secret stream header length", HEADERBYTES, header.length);
        }

        public static void checkKey(byte[] key) {
            checkEqual("secret stream key length", KEYBYTES, key.length);
        }

        public static void checkPush(byte[] message, long messageLen, byte[] cipher) {
            checkArrayLength("message bytes", message, messageLen);
            if (cipher.length < messageLen + ABYTES) {
                throw new IllegalArgumentException("Cipher array too small for messageLen + header");
            }
        }

        public static void checkPull(byte[] cipher, long cipherLen, byte[] message) {
            checkArrayLength("message bytes", cipher, cipherLen);
            if (message.length < cipherLen - ABYTES) {
                throw new IllegalArgumentException("Message array too small for cipherLen - header");
            }
        }

    }



    interface Native {

        /**
         * Generate a secret stream key.
         * @param key The key of size {@link #KEYBYTES}.
         */
        void cryptoSecretStreamKeygen(byte[] key);

        /**
         * Initialises encryption with a state and a key.
         * @param state State to be used in other {@code cryptoSecretStreamPush()} functions.
         * @param header The header of size {@link #HEADERBYTES}.
         * @param key The key as generated by {@link #cryptoSecretStreamKeygen(byte[])}.
         * @return True if successfully initialised state.
         */
        boolean cryptoSecretStreamInitPush(
                State state,
                byte[] header,
                byte[] key
        );

        /**
         * Encrypt a {@code message}.
         * @param state State as initialised in {@link #cryptoSecretStreamInitPush(State, byte[], byte[])}}.
         * @param cipher The resulting cipher of size {@link #ABYTES} + {@code messageLen}.
         * @param cipherAddr The cipher address will be stored here if not null.
         * @param message The message to encrypt.
         * @param messageLen The message length.
         * @param additionalData Additional data.
         * @param additionalDataLen Additional data length.
         * @param tag The tag.
         * @return True if the message was encrypted.
         */
        boolean cryptoSecretStreamPush(
                State state,
                byte[] cipher,
                long[] cipherAddr,
                byte[] message,
                long messageLen,
                byte[] additionalData,
                long additionalDataLen,
                byte tag
        );

        /**
         * Encrypt a {@code message}. This is like {@link #cryptoSecretStreamPush(State, byte[], long[], byte[], long, byte[], long, byte)}
         * but without additional data.
         * @param state State.
         * @param cipher The resulting cipher of size {@link #ABYTES} + {@code messageLen}.
         * @param cipherAddr The cipher address will be stored here if not null.
         * @param message The message to encrypt.
         * @param messageLen The message length.
         * @param tag The tag.
         * @return True if the message was encrypted.
         */
        boolean cryptoSecretStreamPush(
                State state,
                byte[] cipher,
                long[] cipherAddr,
                byte[] message,
                long messageLen,
                byte tag
        );

        /**
         * Encrypt a {@code message}. This is like {@link #cryptoSecretStreamPush(State, byte[], long[], byte[], long, byte[], long, byte)}
         * but without additional data or an address to store the cipher.
         * @param state State as initialised in {@link #cryptoSecretStreamInitPush(State, byte[], byte[])}}.
         * @param cipher The resulting cipher of size {@link #ABYTES} + {@code messageLen}.
         * @param message The message to encrypt.
         * @param messageLen The message length.
         * @param tag The tag.
         * @return True if the message was encrypted.
         */
        boolean cryptoSecretStreamPush(
                State state,
                byte[] cipher,
                byte[] message,
                long messageLen,
                byte tag
        );


        /**
         * Initialises decryption using a state and a key.
         * @param state State to be used in other {@code cryptoSecretStreamPush()} functions.
         * @param header The header of size {@link #HEADERBYTES}.
         * @param key The key as generated by {@link #cryptoSecretStreamKeygen(byte[])}.
         * @return True if successfully initialised state.
         */
        boolean cryptoSecretStreamInitPull(
                State state,
                byte[] header,
                byte[] key
        );


        /**
         * Decrypt a message.
         * @param state The state as put into {@link #cryptoSecretStreamInitPull(State, byte[], byte[])}.
         * @param message The message of size {@code cipherLen} - {@link #ABYTES}.
         * @param messageAddress The place to store the message.
         * @param tag The tag.
         * @param cipher The resulting encrypted message.
         * @param cipherLen The cipher length.
         * @param additionalData Any authenticated data.
         * @param additionalDataLen Authenticated data length.
         * @return True if successful decryption.
         */
        boolean cryptoSecretStreamPull(
                State state,
                byte[] message,
                long[] messageAddress,
                byte[] tag,
                byte[] cipher,
                long cipherLen,
                byte[] additionalData,
                long additionalDataLen
        );

        /**
         * Decrypt a message without additional data.
         * @param state The state as put into {@link #cryptoSecretStreamInitPull(State, byte[], byte[])}.
         * @param message The message of size {@code cipherLen} - {@link #ABYTES}.
         * @param tag The tag.
         * @param cipher The resulting encrypted message.
         * @param cipherLen The cipher length.
         * @return True if successful decryption.
         */
        boolean cryptoSecretStreamPull(
                State state,
                byte[] message,
                byte[] tag,
                byte[] cipher,
                long cipherLen
        );


        /**
         * Explicitly rekeys.
         * @param state The state to update.
         */
        void cryptoSecretStreamRekey(State state);



    }

    interface Lazy {


        /**
         * Generates a key.
         * @return Returns a key that's been through {@link Helpers.Lazy#sodiumBin2Hex(byte[])}.
         */
        Key cryptoSecretStreamKeygen();


        /**
         * Initialise encryption.
         * @param header Header to supply.
         * @param key The key as generated by {@link #cryptoSecretStreamKeygen()}.
         * @return A state which can be further processed by other functions in
         * secret stream.
         */
        State cryptoSecretStreamInitPush(byte[] header, Key key) throws SodiumException;


        /**
         * Encrypt a {@code message}.
         * @param state State as initialised in {@link #cryptoSecretStreamInitPush(byte[], Key)}.
         * @param message The message to encrypt.
         * @param tag The tag.
         * @return The cipher string.
         */
        String cryptoSecretStreamPush(State state, String message, byte tag) throws SodiumException;


        /**
         * Initialises decryption using a state and a key.
         * @param header The header of size {@link #HEADERBYTES}.
         * @param key The key as generated by {@link #cryptoSecretStreamKeygen()}}.
         * @return A state for further processing of decryption functions.
         */
        State cryptoSecretStreamInitPull(byte[] header, Key key) throws SodiumException;


        /**
         * Decrypt a message without additional data.
         * @param state The state as generated by {@link #cryptoSecretStreamInitPull(byte[], Key)}.
         * @param tag The tag.
         * @param cipher The resulting encrypted message.
         * @return The decreypted cipher, i.e the message.
         */
        String cryptoSecretStreamPull(State state, String cipher, byte[] tag) throws SodiumException;

        /**
         * Explicitly rekeys.
         * @param state The state to update.
         */
        void cryptoSecretStreamRekey(State state);

    }


    class State extends Structure {

        public static class ByReference extends State implements Structure.ByReference { }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("k", "nonce", "_pad");
        }

        public byte[] k = new byte[KEYBYTES];
        public byte[] nonce = new byte[NONCEBYTES];
        public byte[] _pad = new byte[8];

    }
}
