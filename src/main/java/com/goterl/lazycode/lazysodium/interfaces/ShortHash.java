/*
 * Copyright (c) Terl Tech Ltd • 08/05/18 23:48 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.BaseChecker;

public interface ShortHash {

    int SIPHASH24_BYTES = 8,
        SIPHASH24_KEYBYTES = 16,
        SIPHASHX24_BYTES = 16,
        SIPHASHX24_KEYBYTES = 16,

        BYTES = SIPHASH24_BYTES,
        KEYBYTES = SIPHASH24_KEYBYTES;



    class Checker extends BaseChecker {

    }



    interface Native {

        /**
         * Short-input hash some text.
         * @param out The hashed text of size {@link #SIPHASH24_BYTES} or
         *            {@link #SIPHASHX24_BYTES} depending on {@code in} size.
         * @param in The short-input text to hash of size {@link #BYTES} or of size {@link #SIPHASHX24_BYTES}.
         * @param inLen The length of the short-input.
         * @param key The key generated via {@link #cryptoShortHashKeygen(byte[])} or
         *            {@link #cryptoShortHashX24Keygen(byte[])}.
         * @return true if success, false if fail.
         */
        boolean cryptoShortHash(byte[] out, byte[] in, long inLen, byte[] key);


        /**
         * Output a 64-bit key.
         * @param k The key of size {@link #SIPHASH24_KEYBYTES}.
         */
        void cryptoShortHashKeygen(byte[] k);

        /**
         * Output a 128-bit key.
         * @param k The key of size {@link #SIPHASHX24_KEYBYTES}.
         */
        void cryptoShortHashX24Keygen(byte[] k);
    }

    interface Lazy {

        /**
         * Hash a short message using a key.
         * @param in The short message to hash.
         * @param key The key generated via {@link #cryptoShortHashKeygen()} or
         *            {@link #cryptoShortHashX24Keygen()}.
         * @return Your message hashed of size {@link #BYTES}.
         */
        String cryptoShortHash(String in, String key) throws SodiumException;

        /**
         * Hash a short message using a key.
         * @param in The short message to hash.
         * @param key The key generated via {@link #cryptoShortHashKeygen()} or
         *            {@link #cryptoShortHashX24Keygen()}.
         * @return Your message hashed of size {@link #SIPHASHX24_BYTES}.
         */
        String cryptoShortHashX24(String in, String key) throws SodiumException;

        /**
         * Generate a 64-bit key for short-input hashing.
         * @return Key in string format.
         */
        String cryptoShortHashKeygen();

        /**
         * Generate a 128-bit key for short-input hashing.
         * @return A 128-bit key in string format.
         */
        String cryptoShortHashX24Keygen();
    }


}
