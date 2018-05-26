/*
 * Copyright (c) Terl Tech Ltd • 12/05/18 16:25 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.BaseChecker;
import com.goterl.lazycode.lazysodium.utils.Constants;
import com.goterl.lazycode.lazysodium.utils.DetachedEncrypt;
import com.goterl.lazycode.lazysodium.utils.KeyPair;

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
         * Get a signing keypair.
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
                Long signedMessageLen,
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
                Long messageLen,
                byte[] signedMessage,
                long signedMessageLen,
                byte[] publicKey
        );

        /**
         * Returns a signature for a message. This
         * does not prepend the signature to the message.
         * See {@link #cryptoSign(byte[], Long, byte[], long, byte[])} for that.
         * @param signature The signature will be added to this byte array.
         * @param sigLength The signature length
         * @param message The message to sign.
         * @param messageLen The message length.
         * @param secretKey The secret key.
         * @return True if the secret key could provide a signature.
         */
        boolean cryptoSignDetached(
                byte[] signature,
                Long sigLength,
                byte[] message,
                long messageLen,
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
         * @see #cryptoSignDetached(byte[], Long, byte[], long, byte[])
         */
        boolean cryptoSignVerifyDetached(byte[] signature, byte[] message, long messageLen, byte[] publicKey);

        /**
         * Converts a public key of ed25519 to curve25519
         * @param curve The array in which the generated key will be placed.
         * @param ed The public key in ed25519.
         * @return Return true if the conversion was successful
         */
        boolean convertPublicKeyEd25519ToCurve25519(byte[] curve, byte[] ed);

        /**
         * Converts a secret key of ed25519 to curve25519
         * @param curve The array in which the generated key will be placed.
         * @param ed The secret key in ed25519.
         * @return Return true if the conversion was successful
         */
        boolean convertSecretKeyEd25519ToCurve25519(byte[] curve, byte[] ed);

    }

    interface Lazy {

        /**
         * Generate a signing keypair.
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
        String cryptoSignOpen(String signedMessage, String publicKey);

        /**
         * Returns a signature for a message. This
         * does not prepend the signature to the message.
         * See {@link #cryptoSign(String, String)} for that.
         * @param message The message to sign.
         * @param secretKey The secret key.
         * @throws SodiumException If could not sign.
         * @return The signature for a message.
         */
        String cryptoSignDetached(String message, String secretKey) throws SodiumException;

        /**
         * Verifies that {@code signature} is valid for the
         * {@code message}.
         * @param signature The signature.
         * @param message The message.
         * @param publicKey The public key that signed the message.
         * @return Returns true if the signature is valid for the message.
         * @see #cryptoSignDetached(String, String)
         */
        boolean cryptoSignVerifyDetached(String signature, String message, String publicKey);

        /**
         * Converts a key pair of ed25519 keys to curve25519
         * @param ed25519KeyPair The key pair.
         * @return curve25519KeyPair
         * */
        KeyPair convertKeyPairEd25519ToCurve25519(KeyPair ed25519KeyPair) throws SodiumException;
    }


}
