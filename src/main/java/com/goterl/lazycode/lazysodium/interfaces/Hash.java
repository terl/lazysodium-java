/*
 * Copyright (c) Terl Tech Ltd • 18/05/18 19:26 • goterl.com
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

public interface Hash {


    int SHA256_BYTES = 32,
        SHA512_BYTES = 64,

        BYTES = SHA512_BYTES;




    class Checker extends BaseChecker {

    }

    interface Native {

        boolean cryptoHashSha256(byte[] out, byte[] in, long inLen);

        boolean cryptoHashSha512(byte[] out, byte[] in, long inLen);


        boolean cryptoHashSha256Init(Hash.State256 state);

        boolean cryptoHashSha256Update(Hash.State256 state,
                                                    byte[] in,
                                                    long inLen);

        boolean cryptoHashSha256Final(Hash.State256 state, byte[] out);


        boolean cryptoHash512Init(Hash.State512 state);

        boolean cryptoHash512Update(Hash.State512 state,
                                                    byte[] in,
                                                    long inLen);

        boolean cryptoHash512Final(Hash.State512 state, byte[] out);

    }

    interface Lazy {

        String cryptoHashSha256(String message);

        String cryptoHashSha512(String message);

        boolean cryptoHashSha256Init(Hash.State256 state);

        boolean cryptoHashSha256Update(Hash.State256 state, String messagePart);

        String cryptoHashSha256Final(Hash.State256 state);

        boolean cryptoHash512Init(Hash.State512 state);

        boolean cryptoHash512Update(Hash.State512 state, String messagePart);

        String cryptoHash512Final(Hash.State512 state);

    }


    class State256 extends Structure {

        public static class ByReference extends State256 implements Structure.ByReference { }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("state", "count", "buf");
        }

        public byte[] state = new byte[8];
        int count;
        public byte[] buf = new byte[64];

    }

    class State512 extends Structure {

        public static class ByReference extends State512 implements Structure.ByReference { }

        @Override
        protected List<String> getFieldOrder() {
            return Arrays.asList("state", "count", "buf");
        }

        public byte[] state = new byte[8];
        public byte[] count = new byte[2];
        public byte[] buf = new byte[128];

    }

}
