/*
 * Copyright (c) Terl Tech Ltd • 09/05/18 01:11 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.utils.BaseChecker;
import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public interface GenericHash {

    int SIPHASH24_BYTES = 8,
        SIPHASH24_KEYBYTES = 16,
        BLAKE2B_BYTES_MAX = 64,
        BLAKE2B_BYTES_MIN = 16,
        BLAKE2B_KEYBYTES_MIN = 16,
        BLAKE2B_KEYBYTES_MAX = 64,

        BYTES = SIPHASH24_BYTES,
        KEYBYTES = SIPHASH24_KEYBYTES,

        BYTES_MAX = BLAKE2B_BYTES_MAX,
        BYTES_MIN = BLAKE2B_BYTES_MIN,

        KEYBYTES_MIN = BLAKE2B_KEYBYTES_MIN,
        KEYBYTES_MAX = BLAKE2B_KEYBYTES_MAX;


    class Checker extends BaseChecker {

    }

    interface Native {

        void cryptoGenericHashKeygen(byte[] k);

        int cryptoGenericHash(
                byte[] out, int outLen,
                byte[] in, long inLen,
                byte[] key, int keyLen
        );

        int cryptoGenericHashInit(GenericHash.State state,
                                   byte[] key,
                                   int keyLength,
                                   int outLen);

        int cryptoGenericHashUpdate(GenericHash.State state,
                                     byte[] in,
                                     long inLen);

        int cryptoGenericHashFinal(GenericHash.State state, byte[] out, int outLen);

    }

    interface Lazy {

    }


    class State extends Structure {

        public static class ByReference extends GenericHash.State implements Structure.ByReference { }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("h", "t", "last_node");
        }

        public Long[] h = new Long[8];
        public Long[] t = new Long[2];
        public int last_node;

    }


}
