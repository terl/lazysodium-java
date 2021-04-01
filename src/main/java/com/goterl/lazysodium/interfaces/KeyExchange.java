/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import com.goterl.lazysodium.utils.SessionPair;

public interface KeyExchange {

    int PUBLICKEYBYTES = 32;
    int SECRETKEYBYTES = 32;
    int SESSIONKEYBYTES = 32;
    int SEEDBYTES = 32;
    String PRIMITIVE = "x25519blake2b";


    interface Native {

        /**
         * Generate a public and a secret key.
         * @param publicKey Public key will be populated here of size {@link #PUBLICKEYBYTES}.
         * @param secretKey Secret key will be populated here of size {@link #SECRETKEYBYTES}.
         * @return True if generated successfully.
         */
        boolean cryptoKxKeypair(byte[] publicKey, byte[] secretKey);

        /**
         * Deterministically generate a public and secret key.
         * Store the seed somewhere if you want to generate these
         * keys again.
         * @param publicKey Public key will be populated here of size {@link #PUBLICKEYBYTES}.
         * @param secretKey Secret key will be populated here of size {@link #SECRETKEYBYTES}.
         * @param seed A random seed of size {@link #SEEDBYTES}.
         * @return True if generated successfully.
         */
        boolean cryptoKxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed);

        /**
         * This function computes a pair of shared keys
         * (rx and tx) using the client's public key clientPk,
         * the client's secret key clientSk and the server's public key serverPk.
         * @param rx Shared key 1 of size {@link #SESSIONKEYBYTES}. This
         *           should be used as an encryption key
         *           to SEND data to the server.
         * @param tx Shared key 2 of size {@link #SESSIONKEYBYTES}. This
         *           should be used as an encryption key to SEND
         *           data to the client FROM the server.
         * @param clientPk Client public key of size {@link #PUBLICKEYBYTES}.
         * @param clientSk Client secret key of size {@link #SECRETKEYBYTES}.
         * @param serverPk Server public key of size {@link #PUBLICKEYBYTES}.
         * @return True if successful or false if the server public key is wrong.
         */
        boolean cryptoKxClientSessionKeys(
                byte[] rx,
                byte[] tx,
                byte[] clientPk,
                byte[] clientSk,
                byte[] serverPk
        );

        /**
         * This function computes a pair of shared keys
         * (rx and tx) using the client's public key clientPk,
         * the server's secret key serverSk and the server's public key serverPk.
         * @param rx Shared key 1 of size {@link #SESSIONKEYBYTES}. This
         *           should be used as an encryption key
         *           to SEND data to the client.
         * @param tx Shared key 2 of size {@link #SESSIONKEYBYTES}. This
         *           should be used as an encryption key to SEND
         *           data to the client FROM the client.
         * @param serverPk Server public key of size {@link #PUBLICKEYBYTES}.
         * @param serverSk Server secret key of size {@link #SECRETKEYBYTES}.
         * @param clientPk Client public key of size {@link #PUBLICKEYBYTES}.
         * @return True if successful or false if the client public key is wrong.
         */
        boolean cryptoKxServerSessionKeys(
                byte[] rx,
                byte[] tx,
                byte[] serverPk,
                byte[] serverSk,
                byte[] clientPk
        );
    }

    interface Lazy {

        /**
         * Generate a public and secret key.
         * @return A KeyPair containing a public and secret key.
         */
        KeyPair cryptoKxKeypair();

        /**
         * Deterministically generate a public and secret key.
         * Store the seed somewhere if you want to generate these
         * keys again.
         * @param seed A random seed of size {@link #SEEDBYTES}.
         * @return The generated key pair.
         */
        KeyPair cryptoKxKeypair(byte[] seed);

        /**
         * Generate a client's session keys. This should
         * be performed on the client.
         * @param clientPk Client public key of size {@link #PUBLICKEYBYTES}.
         * @param clientSk Client secret key of size {@link #SECRETKEYBYTES}.
         * @param serverPk Server public key of size {@link #PUBLICKEYBYTES}.
         * @return A session pair of keys.
         * @throws SodiumException If the size of any of the keys are wrong.
         * @see KeyExchange.Native#cryptoKxClientSessionKeys(byte[], byte[], byte[], byte[], byte[])
         */
        SessionPair cryptoKxClientSessionKeys(
                Key clientPk,
                Key clientSk,
                Key serverPk
        ) throws SodiumException;

        /**
         * Generate a client's session keys. This should
         * be performed on the client.
         * @param clientKeyPair Provide the client's public and private key.
         * @param serverKeyPair Provide the server's public key only.
         * @return Session keys.
         * @throws SodiumException Not provided the correct keys, or generation
         * of session keys failed.
         */
        SessionPair cryptoKxClientSessionKeys(
                KeyPair clientKeyPair,
                KeyPair serverKeyPair
        ) throws SodiumException;


        /**
         * Computes a pair of shared keys (server-side)
         * (rx and tx) using the client's public key clientPk,
         * the server's secret key serverSk and the server's public key serverPk.
         * @param serverPk Server public key of size {@link #PUBLICKEYBYTES}.
         * @param serverSk Server secret key of size {@link #SECRETKEYBYTES}.
         * @param clientPk Client public key of size {@link #PUBLICKEYBYTES}.
         * @return True if successful or false if the client public key is wrong.
         */
        SessionPair cryptoKxServerSessionKeys(
                Key serverPk,
                Key serverSk,
                Key clientPk
        ) throws SodiumException;

        /**
         * Generate a server's session keys. This should
         * be performed on the server.
         * @param serverKeyPair Provide the server's public and private key.
         * @param clientKeyPair Provide the client's public key only.
         * @return Session keys.
         * @throws SodiumException Not provided the correct keys, or generation
         * of session keys failed.
         */
        SessionPair cryptoKxServerSessionKeys(
                KeyPair serverKeyPair,
                KeyPair clientKeyPair
        ) throws SodiumException;
    }


}
