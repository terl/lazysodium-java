/*
 * Copyright (c) Terl Tech Ltd • 23/05/18 15:50 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium;

import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.interfaces.Scrypt;
import com.goterl.lazycode.lazysodium.interfaces.StreamJava;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class LazySodiumJava extends LazySodium implements
        Scrypt.Native, Scrypt.Lazy,
        StreamJava.Native, StreamJava.Lazy {

    private final SodiumJava sodium;

    public LazySodiumJava(SodiumJava sodium) {
        this.sodium = sodium;
    }

    public LazySodiumJava(SodiumJava sodium, Charset charset) {
        super(charset);
        this.sodium = sodium;
    }


    @Override
    public boolean cryptoPwHashScryptSalsa208Sha256(byte[] out, long outLen, byte[] password, long passwordLen, byte[] salt, long opsLimit, long memLimit) {
        return successful(getSodium().crypto_pwhash_scryptsalsa208sha256(out, outLen, password, passwordLen, salt, opsLimit, memLimit));
    }

    @Override
    public boolean cryptoPwHashScryptSalsa208Sha256Str(byte[] out, byte[] password, long passwordLen, long opsLimit, long memLimit) {
        return successful(getSodium().crypto_pwhash_scryptsalsa208sha256_str(out, password, passwordLen, opsLimit, memLimit));
    }

    @Override
    public boolean cryptoPwHashScryptSalsa208Sha256StrVerify(byte[] str, byte[] password, long passwordLen) {
        return successful(getSodium().crypto_pwhash_scryptsalsa208sha256_str_verify(str, password, passwordLen));
    }

    @Override
    public boolean cryptoPwHashScryptSalsa208Sha256Ll(byte[] password, int passwordLen, byte[] salt, int saltLen, long N, long r, long p, byte[] buf, int bufLen) {
        return successful(getSodium().crypto_pwhash_scryptsalsa208sha256_ll(password, passwordLen, salt, saltLen, N, r, p, buf, bufLen));
    }

    @Override
    public boolean cryptoPwHashScryptSalsa208Sha256StrNeedsRehash(byte[] hash, long opsLimit, long memLimit) {
        return successful(getSodium().crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(hash, opsLimit, memLimit));
    }


    // Lazy Scrypt


    @Override
    public String cryptoPwHashScryptSalsa208Sha256(String password, byte[] salt, long opsLimit, long memLimit) throws SodiumException {
        byte[] passwordBytes = bytes(password);
        Scrypt.Checker.checkAllScrypt(passwordBytes.length, salt.length, opsLimit, memLimit);

        byte[] hash = new byte[longToInt(Scrypt.SCRYPTSALSA208SHA256_BYTES_MAX)];
        boolean res = cryptoPwHashScryptSalsa208Sha256(hash, hash.length, passwordBytes, passwordBytes.length, salt, opsLimit, memLimit);

        if (!res) {
            throw new SodiumException("Could not Scrypt hash your password.");
        }

        return toHex(hash);
    }

    @Override
    public String cryptoPwHashScryptSalsa208Sha256Str(String password, long opsLimit, long memLimit) throws SodiumException {
        byte[] passwordBytes = bytes(password);

        if (!Scrypt.Checker.checkOpsLimitScrypt(opsLimit)) {
            throw new SodiumException("The ops limit provided is not between the correct values.");
        }

        if (!Scrypt.Checker.checkMemLimitScrypt(memLimit)) {
            throw new SodiumException("The mem limit provided is not between the correct values.");
        }

        byte[] hash = new byte[longToInt(Scrypt.SCRYPTSALSA208SHA256_STRBYTES)];

        boolean res = cryptoPwHashScryptSalsa208Sha256Str(hash, passwordBytes, passwordBytes.length, opsLimit, memLimit);

        if (!res) {
            throw new SodiumException("Could not string Scrypt hash your password.");
        }

        return toHex(hash);
    }

    @Override
    public boolean cryptoPwHashScryptSalsa208Sha256StrVerify(String hash, String password) {
        byte[] hashBytes = toBin(hash);
        byte[] passwordBytes = bytes(password);

        // If the end of the hash does not have an null byte,
        // let's add it.
        byte endOfHash = hashBytes[hashBytes.length - 1];

        if (endOfHash != 0) {
            byte[] hashWithNullByte = new byte[hashBytes.length + 1];
            System.arraycopy(hashBytes, 0, hashWithNullByte, 0, hashBytes.length);
            hashBytes = hashWithNullByte;
        }

        return cryptoPwHashScryptSalsa208Sha256StrVerify(hashBytes, passwordBytes, passwordBytes.length);
    }


    // Salsa20 12 rounds

    @Override
    public void cryptoStreamSalsa2012Keygen(byte[] key) {
        getSodium().crypto_stream_salsa2012_keygen(key);
    }

    @Override
    public boolean cryptoStreamSalsa2012(byte[] c, long cLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_stream_salsa2012(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamSalsa2012Xor(byte[] cipher, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_stream_salsa2012_xor(cipher, message, messageLen, nonce, key));
    }


    // Salsa20 8 rounds

    @Override
    public void cryptoStreamSalsa208Keygen(byte[] key) {
        getSodium().crypto_stream_salsa208_keygen(key);
    }

    @Override
    public boolean cryptoStreamSalsa208(byte[] c, long cLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_stream_salsa208(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamSalsa208Xor(byte[] cipher, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_stream_salsa208_xor(cipher, message, messageLen, nonce, key));
    }


    public SodiumJava getSodium() {
        return sodium;
    }

}
