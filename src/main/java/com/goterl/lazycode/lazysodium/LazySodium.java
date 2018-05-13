/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.*;
import com.goterl.lazycode.lazysodium.utils.KeyPair;
import com.goterl.lazycode.lazysodium.utils.SessionPair;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class LazySodium implements
        Base,
        Random,
        GenericHash.Native, GenericHash.Lazy,
        ShortHash.Native, ShortHash.Lazy,
        Auth.Native, Auth.Lazy,
        SecretStream.Native, SecretStream.Lazy,
        Padding.Native, Padding.Lazy,
        Helpers.Native, Helpers.Lazy,
        PwHash.Native, PwHash.Lazy,
        Sign.Native, Sign.Lazy,
        Box.Native, Box.Lazy,
        SecretBox.Native, SecretBox.Lazy,
        KeyExchange.Native, KeyExchange.Lazy,
        KeyDerivation.Native, KeyDerivation.Lazy {

    private final Sodium nacl;
    private Charset charset = StandardCharsets.UTF_8;


    public LazySodium(final Sodium sodium) {
        this.nacl = sodium;
        init();
    }

    public LazySodium(final Sodium sodium, Charset charset) {
        this.nacl = sodium;
        this.charset = charset;
        init();
    }

    private void init() {
        // Any common init code here
    }




    //// -------------------------------------------|
    //// HELPERS
    //// -------------------------------------------|

    @Override
    public String sodiumBin2Hex(byte[] bin) {
        return bytesToHex(bin);
    }

    @Override
    public byte[] sodiumHex2Bin(String hex) {
        return hexToBytes(hex);
    }

    /**
     * Equivalent to {@link #sodiumBin2Hex(byte[])}.
     * @param bin Byte array.
     * @return Hexadecimal string.
     */
    public static String toHex(byte[] bin) {
        return bytesToHex(bin);
    }


    /**
     * Binary to hexadecimal.
     * @param hex Hexadecimal string to convert to binary.
     * @return Binary bytes.
     */
    public static byte[] toBin(String hex) {
        return hexToBytes(hex);
    }


    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    // The following is from https://stackoverflow.com/a/9855338/3526705
    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    // The following is from https://stackoverflow.com/a/140861/3526705
    private static byte[] hexToBytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }




    //// -------------------------------------------|
    //// RANDOM
    //// -------------------------------------------|

    @Override
    public byte randomBytesRandom() {
        return nacl.randombytes_random();
    }

    @Override
    public byte[] randomBytesBuf(int size) {
        byte[] bs = new byte[size];
        nacl.randombytes_buf(bs, size);
        return bs;
    }

    @Override
    public byte[] nonce(int size) {
        return randomBytesBuf(size);
    }

    @Override
    public byte randomBytesUniform(int upperBound) {
        return nacl.randombytes_uniform(upperBound);
    }

    @Override
    public byte[] randomBytesDeterministic(int size, byte[] seed) {
        byte[] bs = new byte[size];
        nacl.randombytes_buf_deterministic(bs, size, seed);
        return bs;
    }



    //// -------------------------------------------|
    //// PADDING
    //// -------------------------------------------|

    @Override
    public boolean sodiumPad(int paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize, int maxBufLen) {
        return boolify(nacl.sodium_pad(paddedBuffLen, buf, unpaddedBufLen, blockSize, maxBufLen));
    }

    @Override
    public boolean sodiumUnpad(int unPaddedBuffLen, char[] buf, int paddedBufLen, int blockSize) {
        return boolify(nacl.sodium_unpad(unPaddedBuffLen, buf, paddedBufLen, blockSize));
    }




    //// -------------------------------------------|
    //// KDF KEYGEN
    //// -------------------------------------------|

    @Override
    public void cryptoKdfKeygen(byte[] masterKey) {
        nacl.crypto_kdf_keygen(masterKey);
    }

    @Override
    public String cryptoKdfKeygen(Charset charset) {
        byte[] masterKeyInBytes = new byte[KeyDerivation.MASTER_KEY_BYTES];
        nacl.crypto_kdf_keygen(masterKeyInBytes);
        return sodiumBin2Hex(masterKeyInBytes);
    }

    @Override
    public String cryptoKdfKeygen() {
        byte[] masterKey = new byte[KeyDerivation.MASTER_KEY_BYTES];
        nacl.crypto_kdf_keygen(masterKey);
        return sodiumBin2Hex(masterKey);
    }

    @Override
    public String cryptoKdfDeriveFromKey(int lengthOfSubkey, long subKeyId, String context, byte[] masterKey)
            throws SodiumException {
        return cryptoKdfDeriveFromKey(lengthOfSubkey, subKeyId, context, sodiumBin2Hex(masterKey));
    }

    @Override
    public String cryptoKdfDeriveFromKey(int lengthOfSubkey, long subKeyId, String context, String masterKey)
            throws SodiumException {
        if (!KeyDerivation.Checker.subKeyIsCorrect(lengthOfSubkey)) {
            throw new SodiumException("Subkey is not between the correct lengths.");
        }
        if (!KeyDerivation.Checker.masterKeyIsCorrect(sodiumHex2Bin(masterKey).length)) {
            throw new SodiumException("Master key is not the correct length.");
        }
        if (!KeyDerivation.Checker.contextIsCorrect(bytes(context).length)) {
            throw new SodiumException("Context is not the correct length.");
        }
        byte[] subKey = new byte[lengthOfSubkey];
        byte[] contextAsBytes = bytes(context);
        byte[] masterKeyAsBytes = sodiumHex2Bin(masterKey);
        int res = nacl.crypto_kdf_derive_from_key(
                subKey,
                lengthOfSubkey,
                subKeyId,
                contextAsBytes,
                masterKeyAsBytes
        );
        return res(res, sodiumBin2Hex(subKey));
    }

    @Override
    public int cryptoKdfDeriveFromKey(byte[] subKey, int subKeyLen, long subKeyId, byte[] context, byte[] masterKey) {
        return nacl.crypto_kdf_derive_from_key(subKey, subKeyLen, subKeyId, context, masterKey);
    }



    //// -------------------------------------------|
    //// KEY EXCHANGE
    //// -------------------------------------------|

    @Override
    public boolean cryptoKxKeypair(byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_kx_keypair(publicKey, secretKey));
    }

    @Override
    public boolean cryptoKxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        return boolify(nacl.crypto_kx_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoKxClientSessionKeys(byte[] rx, byte[] tx, byte[] clientPk, byte[] clientSk, byte[] serverPk) {
        return boolify(nacl.crypto_kx_client_session_keys(rx, tx, clientPk, clientSk, serverPk));
    }

    @Override
    public boolean cryptoKxServerSessionKeys(byte[] rx, byte[] tx, byte[] serverPk, byte[] serverSk, byte[] clientPk) {
        return boolify(nacl.crypto_kx_server_session_keys(rx, tx, serverPk, serverSk, clientPk));
    }


    // -- Lazy functions

    @Override
    public KeyPair cryptoKxKeypair() {
        byte[] secretKey = randomBytesBuf(KeyExchange.SECRETKEYBYTES);
        byte[] publicKey = randomBytesBuf(KeyExchange.PUBLICKEYBYTES);

        nacl.crypto_kx_keypair(publicKey, secretKey);

        return new KeyPair(toHex(publicKey), toHex(secretKey));
    }

    @Override
    public KeyPair cryptoKxKeypair(byte[] seed) {
        byte[] secretKey = randomBytesBuf(KeyExchange.SECRETKEYBYTES);
        byte[] publicKey = randomBytesBuf(KeyExchange.PUBLICKEYBYTES);

        nacl.crypto_kx_seed_keypair(publicKey, secretKey, seed);

        return new KeyPair(toHex(publicKey), toHex(secretKey));
    }

    @Override
    public SessionPair cryptoKxClientSessionKeys(byte[] clientPk, byte[] clientSk, byte[] serverPk) throws SodiumException {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];

        if (!cryptoKxClientSessionKeys(rx, tx, clientPk, clientSk, serverPk)) {
            throw new SodiumException("Failure in creating client session keys.");
        }

        return new SessionPair(rx, tx);
    }

    @Override
    public SessionPair cryptoKxClientSessionKeys(KeyPair clientKeyPair, KeyPair serverKeyPair) throws SodiumException {
        return cryptoKxClientSessionKeys(clientKeyPair.getPublicKey(), clientKeyPair.getSecretKey(), serverKeyPair.getPublicKey());
    }

    @Override
    public SessionPair cryptoKxServerSessionKeys(byte[] serverPk, byte[] serverSk, byte[] clientPk) throws SodiumException {
        byte[] rx = new byte[KeyExchange.SESSIONKEYBYTES];
        byte[] tx = new byte[KeyExchange.SESSIONKEYBYTES];

        if (!cryptoKxServerSessionKeys(rx, tx, serverPk,  serverSk, clientPk)) {
            throw new SodiumException("Failure in creating server session keys.");
        }

        return new SessionPair(rx, tx);
    }

    @Override
    public SessionPair cryptoKxServerSessionKeys(KeyPair serverKeyPair, KeyPair clientKeyPair) throws SodiumException {
        return cryptoKxServerSessionKeys(serverKeyPair.getPublicKey(), serverKeyPair.getSecretKey(), clientKeyPair.getPublicKey());
    }


    //// -------------------------------------------|
    //// PASSWORD HASHING
    //// -------------------------------------------|

    @Override
    public boolean cryptoPwHash(byte[] outputHash,
                                long outputHashLen,
                                byte[] password,
                                long passwordLen,
                                byte[] salt,
                                long opsLimit,
                                long memLimit,
                                PwHash.Alg alg) {
        int res = nacl.crypto_pwhash(outputHash,
                outputHashLen,
                password,
                passwordLen,
                salt,
                opsLimit,
                memLimit,
                alg.getValue());
        return boolify(res);
    }

    @Override
    public boolean cryptoPwHashStr(byte[] outputStr,
                                   byte[] password,
                                   long passwordLen,
                                   long opsLimit,
                                   long memLimit) {
        int res = nacl.crypto_pwhash_str(outputStr, password, passwordLen, opsLimit, memLimit);
        return boolify(res);
    }

    @Override
    public boolean cryptoPwHashStrVerify(byte[] hash, byte[] password, long passwordLen) {
        return boolify(nacl.crypto_pwhash_str_verify(hash, password, passwordLen));
    }

    @Override
    public boolean cryptoPwHashStrNeedsRehash(byte[] hash, long opsLimit, long memLimit) {
        return boolify(nacl.crypto_pwhash_str_needs_rehash(hash, opsLimit, memLimit));
    }

    @Override
    public byte[] cryptoPwHash(int lengthOfHash, byte[] password, byte[] salt, long opsLimit, long memLimit, PwHash.Alg alg)
            throws SodiumException {
        PwHash.Checker.checkAll(password.length, salt.length, opsLimit, memLimit);
        byte[] hash = new byte[lengthOfHash];
        cryptoPwHash(hash, hash.length, password, password.length, salt, opsLimit, memLimit, alg);
        return hash;
    }

    @Override
    public String cryptoPwHashStr(String password, long opsLimit, long memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }
        return str(hash);
    }

    @Override
    public String cryptoPwHashStrRemoveNulls(String password, long opsLimit, long memLimit) throws SodiumException {
        byte[] hash = new byte[PwHash.STR_BYTES];
        byte[] passwordBytes = bytes(password);
        boolean res = cryptoPwHashStr(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);
        if (!res) {
            throw new SodiumException("Password hashing failed.");
        }

        byte[] hashNoNulls = removeNulls(hash);
        return str(hashNoNulls);
    }




    //// -------------------------------------------|
    //// SECRET BOX
    //// -------------------------------------------|
    @Override
    public void cryptoSecretBoxKeygen(byte[] key) {
        nacl.crypto_secretbox_keygen(key);
    }

    @Override
    public boolean cryptoSecretBoxEasy(byte[] cipherText, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return boolify(nacl.crypto_secretbox_easy(cipherText, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxOpenEasy(byte[] message, byte[] cipherText, long cipherTextLen, byte[] nonce, byte[] key) {
        return boolify(nacl.crypto_secretbox_open_easy(message, cipherText, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxDetached(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return boolify(nacl.crypto_secretbox_detached(cipherText, mac, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoSecretBoxOpenDetached(byte[] message, byte[] cipherText, byte[] mac, byte[] cipherTextLen, byte[] nonce, byte[] key) {
        return boolify(nacl.crypto_secretbox_open_detached(message, cipherText, mac, cipherTextLen, nonce, key));
    }


    /// --- Lazy

    @Override
    public String cryptoSecretBoxKeygen() {
        byte[] key = new byte[SecretBox.KEYBYTES];
        cryptoSecretBoxKeygen(key);
        return toHex(key);
    }

    @Override
    public String cryptoSecretBoxEasy(String message, byte[] nonce, String key) throws SodiumException {
        byte[] keyBytes = toBin(key);
        byte[] messageBytes = bytes(message);
        byte[] cipherTextBytes = new byte[SecretBox.MACBYTES + messageBytes.length];

        if (!cryptoSecretBoxEasy(cipherTextBytes, messageBytes, messageBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not encrypt message.");
        }

        return toHex(cipherTextBytes);
    }

    @Override
    public String cryptoSecretBoxOpenEasy(String cipher, byte[] nonce, String key, Charset charset) throws SodiumException {
        byte[] keyBytes = toBin(key);
        byte[] cipherBytes = toBin(cipher);
        byte[] messageBytes = new byte[cipherBytes.length - SecretBox.MACBYTES];


        if (!cryptoSecretBoxOpenEasy(messageBytes, cipherBytes, cipherBytes.length, nonce, keyBytes)) {
            throw new SodiumException("Could not decrypt message.");
        }

        return str(messageBytes, charset);
    }



    //// -------------------------------------------|
    //// CRYPTO BOX
    //// -------------------------------------------|

    @Override
    public boolean cryptoBoxKeypair(byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_box_keypair(publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        return boolify(nacl.crypto_box_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoScalarMultBase(byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_scalarmult_base(publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxEasy(byte[] cipherText, byte[] message, long messageLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_box_easy(cipherText, message, messageLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxOpenEasy(byte[] message, byte[] cipherText, long cipherTextLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_box_open_easy(message, cipherText, cipherTextLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxDetached(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_box_detached(cipherText, mac, message, messageLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxOpenDetached(byte[] message, byte[] cipherText, byte[] mac, byte[] cipherTextLen, byte[] nonce, byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_box_open_detached(message, cipherText, mac, cipherTextLen, nonce, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxBeforeNm(byte[] k, byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_box_beforenm(k, publicKey, secretKey));
    }

    @Override
    public boolean cryptoBoxEasyAfterNm(byte[] cipherText, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return boolify(nacl.crypto_box_easy_afternm(cipherText, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxOpenEasyAfterNm(byte[] message, byte[] cipher, long cLen, byte[] nonce, byte[] key) {
        return boolify(nacl.crypto_box_open_easy_afternm(message, cipher, cLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxDetachedAfterNm(byte[] cipherText, byte[] mac, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return boolify(nacl.crypto_box_detached_afternm(cipherText, mac, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxOpenDetachedAfterNm(byte[] message, byte[] cipherText, byte[] mac, byte[] cipherTextLen, byte[] nonce, byte[] key) {
        return boolify(nacl.crypto_box_open_detached_afternm(message, cipherText, mac, cipherTextLen, nonce, key));
    }

    @Override
    public boolean cryptoBoxSeal(byte[] cipher, byte[] message, long messageLen, byte[] publicKey) {
        return boolify(nacl.crypto_box_seal(cipher, message, messageLen, publicKey));
    }

    @Override
    public boolean cryptoBoxSealOpen(byte[] m, byte[] cipher, long cipherLen, byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_box_seal_open(m, cipher, cipherLen, publicKey, secretKey));
    }

    // -- lazy

    @Override
    public KeyPair cryptoBoxKeypair() throws SodiumException {
        byte[] publicKey = randomBytesBuf(Box.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Box.SECRETKEYBYTES);
        if (!cryptoBoxKeypair(publicKey, secretKey)) {
            throw new SodiumException("Unable to create a public and private key.");
        }
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public KeyPair cryptoBoxSeedKeypair(byte[] seed) throws SodiumException {
        byte[] publicKey = randomBytesBuf(Box.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Box.SECRETKEYBYTES);
        if (!Box.Checker.checkSeed(seed.length)) {
            throw new SodiumException("Seed is incorrect size.");
        }
        if (!cryptoBoxSeedKeypair(publicKey, secretKey, seed)) {
            throw new SodiumException("Unable to create a public and private key.");
        }
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public KeyPair cryptoScalarMultBase(byte[] secretKey) throws SodiumException {
        if (!Box.Checker.checkSecretKey(secretKey.length)) {
            throw new SodiumException("Secret key is incorrect size.");
        }
        byte[] publicKey = randomBytesBuf(Box.PUBLICKEYBYTES);
        cryptoScalarMultBase(publicKey, secretKey);
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public KeyPair cryptoScalarMultBase(String secretKey) throws SodiumException {
        byte[] secretKeyBytes = toBin(secretKey);
        return cryptoScalarMultBase(secretKeyBytes);
    }

    @Override
    public String cryptoBoxEasy(String message, byte[] nonce, KeyPair keyPair) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] cipherBytes = randomBytesBuf(Box.MACBYTES + messageBytes.length);
        boolean res = cryptoBoxEasy(
                cipherBytes,
                messageBytes,
                messageBytes.length,
                nonce,
                keyPair.getPublicKey(),
                keyPair.getSecretKey()
        );
        if (!res) {
            throw new SodiumException("Could not encrypt your message.");
        }
        return toHex(cipherBytes);
    }

    @Override
    public String cryptoBoxOpenEasy(String cipherText, byte[] nonce, KeyPair keyPair) throws SodiumException {
        byte[] cipher = toBin(cipherText);
        byte[] message = randomBytesBuf(cipher.length - Box.MACBYTES);
        boolean res =
                cryptoBoxOpenEasy(message, cipher, cipher.length, nonce, keyPair.getPublicKey(), keyPair.getSecretKey());

        if (!res) {
            throw new SodiumException("Could not decrypt your message.");
        }

        return str(message);
    }




    //// -------------------------------------------|
    //// CRYPTO SIGN
    //// -------------------------------------------|

    @Override
    public boolean cryptoSignKeypair(byte[] publicKey, byte[] secretKey) {
        return boolify(nacl.crypto_sign_keypair(publicKey, secretKey));
    }


    @Override
    public boolean cryptoSignSeedKeypair(byte[] publicKey, byte[] secretKey, byte[] seed) {
        return boolify(nacl.crypto_sign_seed_keypair(publicKey, secretKey, seed));
    }

    @Override
    public boolean cryptoSign(byte[] signedMessage, Long signedMessageLen, byte[] message, long messageLen, byte[] secretKey) {
        return boolify(nacl.crypto_sign(signedMessage, signedMessageLen, message, messageLen, secretKey));
    }

    @Override
    public boolean cryptoSignOpen(byte[] message, Long messageLen, byte[] signedMessage, long signedMessageLen, byte[] publicKey) {
        return boolify(nacl.crypto_sign_open(message, messageLen, signedMessage, signedMessageLen, publicKey));
    }


    // -- lazy

    @Override
    public KeyPair cryptoSignKeypair() throws SodiumException {
        byte[] publicKey = randomBytesBuf(Sign.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Sign.SECRETKEYBYTES);
        if (!cryptoSignKeypair(publicKey, secretKey)) {
            throw new SodiumException("Could not generate a signing keypair.");
        }
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public KeyPair cryptoSignSeedKeypair(byte[] seed) throws SodiumException {
        byte[] publicKey = randomBytesBuf(Sign.PUBLICKEYBYTES);
        byte[] secretKey = randomBytesBuf(Sign.SECRETKEYBYTES);
        if (!cryptoSignSeedKeypair(publicKey, secretKey, seed)) {
            throw new SodiumException("Could not generate a signing keypair with a seed.");
        }
        return new KeyPair(publicKey, secretKey);
    }

    @Override
    public String cryptoSign(String message, String secretKey) throws SodiumException {
        byte[] messageBytes = bytes(message);
        byte[] secretKeyBytes = sodiumHex2Bin(secretKey);
        byte[] signedMessage = randomBytesBuf(Sign.BYTES + messageBytes.length);
        boolean res = cryptoSign(signedMessage, null, messageBytes, messageBytes.length, secretKeyBytes);

        if (!res) {
            throw new SodiumException("Could not sign your message.");
        }

        return sodiumBin2Hex(signedMessage);
    }

    @Override
    public String cryptoSignOpen(String signedMessage, String publicKey) {
        byte[] signedMessageBytes = toBin(signedMessage);
        byte[] publicKeyBytes = sodiumHex2Bin(publicKey);

        byte[] messageBytes = randomBytesBuf(signedMessageBytes.length - Sign.BYTES);

        boolean res = cryptoSignOpen(
                messageBytes,
                null,
                signedMessageBytes,
                signedMessageBytes.length,
                publicKeyBytes
        );

        if (!res) {
            return null;
        }

        return str(messageBytes);
    }



    //// -------------------------------------------|
    //// SECRET SCREAM
    //// -------------------------------------------|

    @Override
    public void cryptoSecretStreamXChacha20Poly1305Keygen(byte[] key) {
        nacl.crypto_secretstream_xchacha20poly1305_keygen(key);
    }

    @Override
    public int cryptoSecretStreamXChacha20Poly1305InitPush(SecretStream.State state, byte[] header, byte[] key) {
        return nacl.crypto_secretstream_xchacha20poly1305_init_push(state, header, key);
    }

    @Override
    public int cryptoSecretStreamXChacha20Poly1305Push(SecretStream.State state, byte[] cipher, Long cipherAddr, byte[] message, long messageLen, byte tag) {
        return nacl.crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                cipherAddr,
                message,
                messageLen,
                new byte[0],
                0L,
                tag
        );
    }

    @Override
    public int cryptoSecretStreamXChacha20Poly1305Push(SecretStream.State state,
                                                       byte[] cipher,
                                                       byte[] message,
                                                       long messageLen,
                                                       byte tag) {
        return nacl.crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                null,
                message,
                messageLen,
                new byte[0],
                0L,
                tag
        );
    }

    @Override
    public int cryptoSecretStreamXChacha20Poly1305Push(SecretStream.State state,
                                                       byte[] cipher,
                                                       Long cipherAddr,
                                                       byte[] message,
                                                       long messageLen,
                                                       byte[] additionalData,
                                                       long additionalDataLen,
                                                       byte tag) {
        return nacl.crypto_secretstream_xchacha20poly1305_push(
                state,
                cipher,
                cipherAddr,
                message,
                messageLen,
                additionalData,
                additionalDataLen,
                tag
        );
    }

    @Override
    public int cryptoSecretStreamXChacha20Poly1305InitPull(SecretStream.State state, byte[] header, byte[] key) {
        return nacl.crypto_secretstream_xchacha20poly1305_init_pull(state, header, key);
    }

    @Override
    public int cryptoSecretStreamXChacha20Poly1305Pull(SecretStream.State state,
                                                       byte[] message,
                                                       Long messageAddress,
                                                       byte tag,
                                                       byte[] cipher,
                                                       long cipherLen,
                                                       byte[] additionalData,
                                                       long additionalDataLen) {
        return nacl.crypto_secretstream_xchacha20poly1305_pull(
                state, message, messageAddress, tag, cipher, cipherLen, additionalData, additionalDataLen
        );
    }

    @Override
    public int cryptoSecretStreamXChacha20Poly1305Pull(SecretStream.State state, byte[] message, byte tag, byte[] cipher, long cipherLen) {
        return nacl.crypto_secretstream_xchacha20poly1305_pull(
                state,
                message,
                null,
                tag,
                cipher,
                cipherLen,
                new byte[0],
                0L
        );
    }


    //// -------------------------------------------|
    //// CRYPTO AUTH
    //// -------------------------------------------|
    @Override
    public int cryptoAuth(byte[] tag, byte[] in, long inLen, byte[] key) {
        return nacl.crypto_auth(tag, in, inLen, key);
    }

    @Override
    public int cryptoAuthVerify(byte[] tag, byte[] in, long inLen, byte[] key) {
        return nacl.crypto_auth_verify(tag, in, inLen, key);
    }

    @Override
    public void cryptoAuthKeygen(byte[] k) {
        nacl.crypto_auth_keygen(k);
    }




    //// -------------------------------------------|
    //// SHORT HASH
    //// -------------------------------------------|
    @Override
    public boolean cryptoShortHash(byte[] out, byte[] in, long inLen, byte[] key) {
        return boolify(nacl.crypto_shorthash(out, in, inLen, key));
    }

    @Override
    public void cryptoShortHashKeygen(byte[] k) {
        nacl.crypto_shorthash_keygen(k);
    }

    @Override
    public void cryptoShortHashX24Keygen(byte[] k) {
        nacl.crypto_shorthash_keygen(k);
    }

    @Override
    public String cryptoShortHash(String in, String key) throws SodiumException {
        byte[] inBytes = hexToBytes(in);
        byte[] keyBytes = hexToBytes(key);
        byte[] out = randomBytesBuf(ShortHash.BYTES);
        if (nacl.crypto_shorthash(out, inBytes, inBytes.length, keyBytes) != 0) {
            throw new SodiumException("Failed short-input hashing.");
        }
        return sodiumBin2Hex(out);
    }

    @Override
    public String cryptoShortHashX24(String in, String key) throws SodiumException {
        byte[] inBytes = hexToBytes(in);
        byte[] keyBytes = hexToBytes(key);
        byte[] out = randomBytesBuf(ShortHash.SIPHASHX24_KEYBYTES);
        if (nacl.crypto_shorthash_siphashx24(out, inBytes, inBytes.length, keyBytes) != 0) {
            throw new SodiumException("Failed short-input hashing.");
        }
        return sodiumBin2Hex(out);
    }

    @Override
    public String cryptoShortHashKeygen() {
        byte[] key = randomBytesBuf(ShortHash.SIPHASH24_KEYBYTES);
        nacl.crypto_shorthash_keygen(key);
        return sodiumBin2Hex(key);
    }

    @Override
    public String cryptoShortHashX24Keygen() {
        byte[] key = randomBytesBuf(ShortHash.SIPHASHX24_KEYBYTES);
        nacl.crypto_shorthash_keygen(key);
        return sodiumBin2Hex(key);
    }




    //// -------------------------------------------|
    //// GENERIC HASH
    //// -------------------------------------------|

    @Override
    public boolean cryptoGenericHash(byte[] out, int outLen, byte[] in, long inLen, byte[] key, int keyLen) {
        return boolify(nacl.crypto_generichash(out, outLen, in, inLen, key, keyLen));
    }

    @Override
    public boolean cryptoGenericHashInit(GenericHash.State state, byte[] key, int keyLength, int outLen) {
        return boolify(nacl.crypto_generichash_init(state, key, keyLength, outLen));
    }

    @Override
    public boolean cryptoGenericHashUpdate(GenericHash.State state, byte[] in, long inLen) {
        return boolify(nacl.crypto_generichash_update(state, in, inLen));
    }

    @Override
    public boolean cryptoGenericHashFinal(GenericHash.State state, byte[] out, int outLen) {
        return boolify(nacl.crypto_generichash_final(state, out, outLen));
    }

    @Override
    public void cryptoGenericHashKeygen(byte[] k) {
        nacl.crypto_generichash_keygen(k);
    }

    // -- lazy

    @Override
    public String cryptoGenericHashKeygen() {
        byte[] key = randomBytesBuf(GenericHash.KEYBYTES_MAX);
        cryptoGenericHashKeygen(key);
        return toHex(key);
    }

    @Override
    public String cryptoGenericHash(String in) throws SodiumException {
        byte[] message = bytes(in);
        byte[] hash = randomBytesBuf(GenericHash.BYTES_MAX);
        boolean res = cryptoGenericHash(hash, hash.length, message, message.length, null, 0);

        if (!res) {
            throw new SodiumException("Error could not hash the message.");
        }

        return toHex(hash);
    }

    @Override
    public String cryptoGenericHash(String in, String key) throws SodiumException {

        byte[] message = bytes(in);
        byte[] hash = randomBytesBuf(GenericHash.BYTES_MAX);
        byte[] keyBytes = toBin(key);

        boolean res = cryptoGenericHash(hash, hash.length, message, message.length, keyBytes, keyBytes.length);

        if (!res) {
            throw new SodiumException("Could not hash the message.");
        }

        return toHex(hash);
    }

    @Override
    public boolean cryptoGenericHashInit(GenericHash.State state, String key, int outLen) {
        byte[] keyBytes = toBin(key);
        return cryptoGenericHashInit(state, keyBytes, keyBytes.length, outLen);
    }

    @Override
    public String cryptoGenericHashUpdate(GenericHash.State state, String in) {
        byte[] inBytes = bytes(in);
        cryptoGenericHashUpdate(state, inBytes, inBytes.length);
        return toHex(inBytes);
    }

    @Override
    public String cryptoGenericHashFinal(GenericHash.State state, int outLen) {
        byte[] out = randomBytesBuf(outLen);
        cryptoGenericHashFinal(state, out, outLen);
        return toHex(out);
    }






    //// -------------------------------------------|
    //// CONVENIENCE
    //// -------------------------------------------|

    @Override
    public <T> T res(int res, T object) {
        return (res != 0) ? null : object;
    }

    @Override
    public boolean boolify(int res) {
        return (res == 0);
    }

    @Override
    public String str(byte[] bs) {
        return new String(bs, charset);
    }

    @Override
    public String str(byte[] bs, Charset charset) {
        if (charset == null) {
            return new String(bs, this.charset);
        }
        return new String(bs, charset);
    }

    @Override
    public byte[] bytes(String s) {
        return s.getBytes(charset);
    }

    @Override
    public boolean wrongLen(byte[] bs, int shouldBe) {
        return bs.length != shouldBe;
    }

    @Override
    public boolean wrongLen(int byteLength, int shouldBe) {
        return byteLength != shouldBe;
    }

    @Override
    public boolean wrongLen(int byteLength, long shouldBe) {
        return byteLength != shouldBe;
    }

    @Override
    public byte[] removeNulls(byte[] bs) {
        // First determine how many bytes to
        // cut off the end by checking total of null bytes
        int totalBytesToCut = 0;
        for (int i = bs.length - 1; i >= 0; i--) {
            byte b = bs[i];
            if (b == 0) {
                totalBytesToCut++;
            }
        }

        // ... then we now can copy across the array
        // without the null bytes.
        int newLengthOfBs = bs.length - totalBytesToCut;
        byte[] trimmed = new byte[newLengthOfBs];
        System.arraycopy(bs, 0, trimmed, 0, newLengthOfBs);

        return trimmed;
    }



    // --
    //// -------------------------------------------|
    //// MAIN
    //// -------------------------------------------|
    // --
    public static void main(String[] args) {
        // Can implement some code here to test
    }



}
