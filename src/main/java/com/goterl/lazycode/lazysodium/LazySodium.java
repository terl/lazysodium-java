/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.google.common.io.BaseEncoding;
import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.*;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class LazySodium implements
        Base,
        Random,
        Padding.Native, Padding.Lazy,
        Helpers.Native, Helpers.Lazy,
        PwHash.Native, PwHash.Lazy,
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
        return BaseEncoding.base16().encode(bin);
    }

    @Override
    public byte[] sodiumHex2Bin(String hex) {
        return BaseEncoding.base16().decode(hex);
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
    public byte randomBytesUniform(byte upperBound) {
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
        return res(res, str(subKey));
    }

    @Override
    public int cryptoKdfDeriveFromKey(byte[] subKey, int subKeyLen, long subKeyId, byte[] context, byte[] masterKey) {
        return nacl.crypto_kdf_derive_from_key(subKey, subKeyLen, subKeyId, context, masterKey);
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
    public byte[] cryptoPwHash(byte[] password, byte[] salt, long opsLimit, long memLimit, PwHash.Alg alg)
            throws SodiumException {
        PwHash.Checker.checkAll(password.length, salt.length, opsLimit, memLimit);
        byte[] hash = new byte[CryptoBox.SEEDBYTES];
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
