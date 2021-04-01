/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.Constants;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.utils.KeyPair;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

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


    interface Native {

        /**
         * Useful for signing a multi-part message (Ed25519ph).
         * If the message can fit in memory and can be supplied as a
         * single chunk, the single-part API should be preferred.
         * This function must be called before the first crypto_sign_update() call.
         * @param state The state.
         * @return True if successful.
         */
        boolean cryptoSignInit(Sign.StateCryptoSign state);

        /**
         * Add a new chunk of length chunkLen bytes to the
         * message that will eventually be signed.
         * @param state The state.
         * @param chunk A part of the long message.
         * @param chunkLength Message length.
         * @return True if this chunk was successfully signed.
         */
        boolean cryptoSignUpdate(Sign.StateCryptoSign state, byte[] chunk, long chunkLength);

        /**
         * This function computes a signature for the previously supplied message,
         * using the secret key sk and puts it into sig.
         * If sigLen is not NULL, the length of the signature is stored at this address.
         * However this is kind of redundant as you can just do sig.length.
         * @param state The state.
         * @param sig Resultant signature.
         * @param sigLen Signature length.
         * @param sk Secret key.
         * @return True if successfully signed completely.
         */
        boolean cryptoSignFinalCreate(Sign.StateCryptoSign state, byte[] sig, Pointer sigLen, byte[] sk);

        /**
         * Verifies that sig is a valid signature for the message whose
         * content has been previously supplied using crypto_update(),
         * using the public key pk.
         * @param state The state.
         * @param sig Resultant signature.
         * @param pk Secret key.
         * @return True if successfully signed completely.
         */
        boolean cryptoSignFinalVerify(Sign.StateCryptoSign state, byte[] sig, byte[] pk);

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
         * @param message The message.
         * @param messageLen The message length.
         * @param secretKey The secret key.
         * @return True if successfully signed.
         */
        boolean cryptoSign(
                byte[] signedMessage,
                byte[] message,
                long messageLen,
                byte[] secretKey
        );

        /**
         * Verify a signed message.
         * @param message The message will be placed in here.
         * @param signedMessage The signed message.
         * @param signedMessageLen The signed message length.
         * @param publicKey Public key.
         * @return True if the signature is from the public key.
         */
        boolean cryptoSignOpen(
                byte[] message,
                byte[] signedMessage,
                long signedMessageLen,
                byte[] publicKey
        );

        /**
         * Returns a signature for a message. This
         * does not prepend the signature to the message.
         * See {@link #cryptoSign(byte[], byte[], long, byte[])} for that.
         * @param signature The signature will be added to this byte array.
         * @param message The message to sign.
         * @param messageLen The message length.
         * @param secretKey The secret key.
         * @return True if the secret key could provide a signature.
         */
        boolean cryptoSignDetached(
                byte[] signature,
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
         * @see #cryptoSignDetached(byte[], byte[], long, byte[])
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
         * Sign a message.
         * @param message The message to sign.
         * @param secretKey The secret key.
         * @return A {@link Helpers.Lazy#sodiumBin2Hex(byte[])}-ified signed message.
         */
        String cryptoSign(String message, Key secretKey) throws SodiumException;

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


    class StateCryptoSign extends Structure {
        public Hash.State512 hs;

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("hs");
        }

        @Override
        public StateCryptoSign clone() {
            StateCryptoSign state2 = new StateCryptoSign();
            state2.hs.count = hs.count.clone();
            state2.hs.state = hs.state.clone();
            state2.hs.buf = hs.buf.clone();
            return state2;
        }
    }

}
