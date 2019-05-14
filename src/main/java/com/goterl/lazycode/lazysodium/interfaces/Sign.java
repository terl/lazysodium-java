/*
 * Copyright (c) Terl Tech Ltd • 12/05/18 16:25 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.*;
import com.sun.jna.NativeLong;

public interface Sign {


    int ED25519_PUBLICKEYBYTES = 32,
        ED25519_BYTES = 64,
        ED25519_SECRETKEYBYTES = 64,
        ED25519_SEEDBYTES = 32,
        CURVE25519_PUBLICKEYBYTES = 32,
        CURVE25519_SECRETKEYBYTES = 32;

    long ED25519_MESSAGEBYTES_MAX = Constants.SIZE_MAX - ED25519_BYTES;

    int BYTES = ED25519_BYTES,
        PUBLICKEYBYTES = ED25519_PUBLICKEYBYTES,
        SECRETKEYBYTES = ED25519_SECRETKEYBYTES,
        SEEDBYTES = ED25519_SEEDBYTES;

    long MESSAGEBYTES_MAX = ED25519_MESSAGEBYTES_MAX;



    class Checker extends BaseChecker { }


    interface Native {

        /**
         * Generate a signing keypair (ed25519).
         * @param publicKey Public key.
         * @param secretKey Secret key.
         * @return True if successful.
         */
        boolean cryptoSignKeypair(byte[] publicKey, byte[] secretKey);

        /**
         * Deterministically generate a public and secret key.
         * @param publicKey Public key.
         * @param secretKey Secret key.
         * @param seed The seed used to generate the keys.
         * @return True if successfully generated keys.
         */
        boolean cryptoSignSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed);

        /**
         * Sign a message.
         * @param signedMessage Signed message will be placed here.
         *                      It is {@link #BYTES} + {@code messageLen}
         *                      long.
         * @param signedMessageLen The signed message length.
         * @param message The message.
         * @param messageLen The message length.
         * @param secretKey The secret key.
         * @return True if successfully signed.
         */
        boolean cryptoSign(
                byte[] signedMessage,
                long[] signedMessageLen,
                byte[] message,
                long messageLen,
                byte[] secretKey
        );

        /**
         * Verify a signed message.
         * @param message The message will be placed in here.
         * @param messageLen The message length.
         * @param signedMessage The signed message.
         * @param signedMessageLen The signed message length.
         * @param publicKey Public key.
         * @return True if the signature is from the public key.
         */
        boolean cryptoSignOpen(
                byte[] message,
                long[] messageLen,
                byte[] signedMessage,
                long signedMessageLen,
                byte[] publicKey
        );

        /**
         * Returns a signature for a message. This
         * does not prepend the signature to the message.
         * See {@link #cryptoSign(byte[], long[], byte[], long, byte[])} for that.
         * @param signature The signature will be added to this byte array.
         * @param sigLength The signature length
         * @param message The message to sign.
         * @param messageLen The message length.
         * @param secretKey The secret key.
         * @return True if the secret key could provide a signature.
         */
        boolean cryptoSignDetached(
                byte[] signature,
                long[] sigLength,
                byte[] message,
                NativeLong messageLen,
                byte[] secretKey
        );

        /**
         * Verifies that {@code signature} is valid for the
         * {@code message}.
         * @param signature The signature.
         * @param message The message.
         * @param messageLen The message length.
         * @param publicKey The public key that signed the message.
         * @return Returns true if the signature is valid for the message.
         * @see #cryptoSignDetached(byte[], long[], byte[], NativeLong, byte[])
         */
        boolean cryptoSignVerifyDetached(byte[] signature, byte[] message, int messageLen, byte[] publicKey);

        /**
         * Converts a public ed25519 key to a public curve25519 key.
         * @param curve The array in which the generated key will be placed.
         * @param ed The public key in ed25519.
         * @return Return true if the conversion was successful.
         */
        boolean convertPublicKeyEd25519ToCurve25519(byte[] curve, byte[] ed);

        /**
         * Converts a secret ed25519 key to a secret curve25519 key.
         * @param curve The array in which the generated key will be placed.
         * @param ed The secret key in ed25519.
         * @return Return true if the conversion was successful.
         */
        boolean convertSecretKeyEd25519ToCurve25519(byte[] curve, byte[] ed);

        /**
         * Extracts the seed value from a secret ed25519 key.
         * @param seed The array in which the seed value will be placed. Must be Sign.ED25519_SEEDBYTES bytes long.
         * @param ed The secret key in ed25519.
         * @return Return true if the seed is extracted.
         */
        boolean cryptoSignEd25519SkToSeed(byte[] seed, byte[] ed);

        /**
         * Extracts the ed25519 public key from a secret ed25519 key.
         * @param publicKey The array in which the public key will be placed. Must be Sign.PUBLICKEYBYTES bytes long.
         * @param ed The secret key in ed25519.
         * @return Return true if the public key is extracted.
         */
        boolean cryptoSignEd25519SkToPk(byte[] publicKey, byte[] ed);

    }

    interface Lazy {

        /**
         * Generate a signing keypair (ed25519).
         * @return Public and private keypair.
         */
        KeyPair cryptoSignKeypair() throws SodiumException;

        /**
         * Generate a signing keypair deterministically.
         * @param seed The seed to generate keys.
         * @return Public and private keypair.
         */
        KeyPair cryptoSignSeedKeypair(byte[] seed) throws SodiumException;

        /**
         * Generate a signing keypair (ed25519), given a secret ed25519 key.
         * @param secretKey The ed25519 secret key.
         * @return The private and public ed25519 keys.
         */
        KeyPair cryptoSignSecretKeyPair(Key secretKey) throws SodiumException;

        /**
         * Sign a message.
         * @param message The message to sign.
         * @param secretKey The secret key.
         * @return A {@link Helpers.Lazy#sodiumBin2Hex(byte[])}-ified signed message.
         */
        String cryptoSign(String message, String secretKey) throws SodiumException;

        /**
         * Checks that a message is validly signed by a public key.
         * @param signedMessage The signed message.
         * @param publicKey The public key that signed the message.
         * @return Returns the message without a signature. If null, then
         * the message is not validly signed by the publicKey.
         */
        String cryptoSignOpen(String signedMessage, Key publicKey);

        /**
         * Returns a signature for a message. This
         * does not prepend the signature to the message.
         * See {@link #cryptoSign(String, String)} for that.
         * @param message The message to sign.
         * @param secretKey The secret key.
         * @throws SodiumException If could not sign.
         * @return The signature for a message.
         */
        String cryptoSignDetached(String message, Key secretKey) throws SodiumException;

        /**
         * Verifies that {@code signature} is valid for the
         * {@code message}.
         * @param signature The signature.
         * @param message The message.
         * @param publicKey The public key that signed the message.
         * @return Returns true if the signature is valid for the message.
         * @see #cryptoSignDetached(String, Key)
         */
        boolean cryptoSignVerifyDetached(String signature, String message, Key publicKey);

        /**
         * Converts a ed25519 keypair to a curve25519 keypair.
         * @param ed25519KeyPair The key pair.
         * @return curve25519KeyPair
         * @throws SodiumException If conversion was unsuccessful.
         * */
        KeyPair convertKeyPairEd25519ToCurve25519(KeyPair ed25519KeyPair) throws SodiumException;
    }


}
