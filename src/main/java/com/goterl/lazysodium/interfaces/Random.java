/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;



public interface Random {

    /**
     * Return a unsigned int byte 0 and 0xffffffff included.
     * @return A random byte.
     */
    long randomBytesRandom();

    /**
     * Returns an unpredictable value between 0 and upperBound (excluded).
     * Unlike randombytes_random() % upper_bound, it guarantees a uniform distribution
     * of the possible output values even when upper_bound is not a power of 2. Note
     * that an upper_bound less than 2 leaves only a single element to be chosen, namely 0.
     * @param upperBound
     * @return A uniformly random unsigned int.
     */
    long randomBytesUniform(int upperBound);

    /**
     * Get a random number of bytes.
     * @param size The length of the byte array to return.
     * @return Random byte array.
     */
    byte[] randomBytesBuf(int size);

    /**
     * Get deterministically random bytes given a seed.
     * @param size Size of byte array to return.
     * @param seed Seed to provide.
     * @return Deterministically random byte array.
     */
    byte[] randomBytesDeterministic(int size, byte[] seed);


    /**
     * Get a random number of bytes to use in a nonce.
     * @param size The size of the byte array to return.
     * @return Random nonce array.
     * @see #randomBytesBuf(int)
     */
    byte[] nonce(int size);
}
