/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.interfaces.Scrypt;
import com.goterl.lazysodium.interfaces.StreamJava;
import com.goterl.lazysodium.utils.Key;
import com.goterl.lazysodium.interfaces.MessageEncoder;

import java.nio.charset.Charset;

public class LazySodiumJava extends LazySodium implements
        Scrypt.Native, Scrypt.Lazy,
        StreamJava.Native, StreamJava.Lazy {

    private final SodiumJava sodium;

    public LazySodiumJava(SodiumJava sodium) {
        super();
        this.sodium = sodium;
    }

    public LazySodiumJava(SodiumJava sodium, Charset charset) {
        super(charset);
        this.sodium = sodium;
    }

    public LazySodiumJava(SodiumJava sodium, MessageEncoder messageEncoder) {
        super(messageEncoder);
        this.sodium = sodium;
    }

    public LazySodiumJava(SodiumJava sodium, Charset charset, MessageEncoder messageEncoder) {
        super(charset, messageEncoder);
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
    public String cryptoPwHashScryptSalsa208Sha256(String password, long hashLen, byte[] salt, long opsLimit, long memLimit) throws SodiumException {
        byte[] passwordBytes = bytes(password);
        Scrypt.Checker.checkAllScrypt(passwordBytes.length, salt.length, hashLen, opsLimit, memLimit);

        byte[] hash = new byte[longToInt(hashLen)];
        boolean res = cryptoPwHashScryptSalsa208Sha256(hash, hash.length, passwordBytes, passwordBytes.length, salt, opsLimit, memLimit);

        if (!res) {
            throw new SodiumException("Could not Scrypt hash your password.");
        }

        return messageEncoder.encode(hash);
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

        return messageEncoder.encode(hash);
    }

    @Override
    public boolean cryptoPwHashScryptSalsa208Sha256StrVerify(String hash, String password) {
        byte[] hashBytes = messageEncoder.decode(hash);
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

    @Override
    public void cryptoStreamXChaCha20Keygen(byte[] key) {
        getSodium().crypto_stream_xchacha20_keygen(key);
    }


    @Override
    public boolean cryptoStreamXChaCha20(byte[] c, long cLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_stream_xchacha20(c, cLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamXChaCha20Xor(byte[] cipher, byte[] message, long messageLen, byte[] nonce, byte[] key) {
        return successful(getSodium().crypto_stream_xchacha20_xor(cipher, message, messageLen, nonce, key));
    }

    @Override
    public boolean cryptoStreamXChaCha20Ic(byte[] cipher, byte[] message, long messageLen, byte[] nonce, long ic, byte[] key) {
        return successful(getSodium().crypto_stream_xchacha20_xor_ic(cipher, message, messageLen, nonce, ic, key));
    }

    // lazy


    @Override
    public Key cryptoStreamKeygen(StreamJava.Method method) {
        byte[] k;
        if (method.equals(StreamJava.Method.SALSA20_8)) {
            k = new byte[StreamJava.SALSA208_KEYBYTES];
            getSodium().crypto_stream_salsa208_keygen(k);
        } else if (method.equals(StreamJava.Method.SALSA20_12)) {
            k = new byte[StreamJava.SALSA2012_KEYBYTES];
            getSodium().crypto_stream_salsa2012_keygen(k);
        } else {
            k = new byte[StreamJava.XCHACHA20_KEYBYTES];
            getSodium().crypto_stream_xchacha20_keygen(k);
        }
        return Key.fromBytes(k);
    }

    @Override
    public byte[] cryptoStream(byte[] nonce, Key key, StreamJava.Method method) {
        byte[] c = new byte[20];
        int cLen = c.length;
        if (method.equals(StreamJava.Method.SALSA20_8)) {
            getSodium().crypto_stream_salsa208(c, cLen, nonce, key.getAsBytes());
        } else if (method.equals(StreamJava.Method.SALSA20_12)) {
            getSodium().crypto_stream_salsa2012(c, cLen, nonce, key.getAsBytes());
        } else {
            getSodium().crypto_stream_xchacha20(c, cLen, nonce, key.getAsBytes());
        }
        return c;
    }

    @Override
    public String cryptoStreamXor(String message, byte[] nonce, Key key, StreamJava.Method method) {
        byte[] mBytes = bytes(message);
        return messageEncoder.encode(cryptoStreamDefaultXor(mBytes, nonce, key, method));
    }

    @Override
    public String cryptoStreamXorDecrypt(String cipher, byte[] nonce, Key key, StreamJava.Method method) {
        return str(cryptoStreamDefaultXor(messageEncoder.decode(cipher), nonce, key, method));
    }

    @Override
    public String cryptoStreamXorIc(String message, byte[] nonce, long ic, Key key, StreamJava.Method method) {
        byte[] mBytes = bytes(message);
        return messageEncoder.encode(cryptoStreamDefaultXorIc(mBytes, nonce, ic, key, method));
    }

    @Override
    public String cryptoStreamXorIcDecrypt(String cipher, byte[] nonce, long ic, Key key, StreamJava.Method method) {
        return str(cryptoStreamDefaultXorIc(messageEncoder.decode(cipher), nonce, ic, key, method));
    }

    private byte[] cryptoStreamDefaultXor(byte[] messageBytes, byte[] nonce, Key key, StreamJava.Method method) {
        int mLen = messageBytes.length;
        byte[] cipher = new byte[mLen];
        if (method.equals(StreamJava.Method.SALSA20_8)) {
            cryptoStreamSalsa208Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        } else if (method.equals(StreamJava.Method.SALSA20_12)) {
            cryptoStreamSalsa2012Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        } else {
            cryptoStreamXChaCha20Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        }
        return cipher;
    }

    private byte[] cryptoStreamDefaultXorIc(byte[] messageBytes, byte[] nonce, long ic, Key key, StreamJava.Method method) {
        int mLen = messageBytes.length;
        byte[] cipher = new byte[mLen];
        if (method.equals(StreamJava.Method.SALSA20_8)) {
            cryptoStreamSalsa208Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        } else if (method.equals(StreamJava.Method.SALSA20_12)) {
            cryptoStreamSalsa2012Xor(cipher, messageBytes, mLen, nonce, key.getAsBytes());
        } else {
            cryptoStreamXChaCha20Ic(cipher, messageBytes, mLen, nonce, ic, key.getAsBytes());
        }
        return cipher;
    }


    public SodiumJava getSodium() {
        return sodium;
    }

}
