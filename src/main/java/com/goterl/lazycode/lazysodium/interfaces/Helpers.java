/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


public interface Helpers {

    interface Native {

    }

    interface Lazy {

        /**
         * This method does not null terminate strings.
         * @param bin The binary bytes you want to convert to strings.
         * @return Hexadecimal string
         */
        String sodiumBin2Hex(byte[] bin);

        /**
         * Hexadecimal to binary. Does not null terminate the binary
         * array.
         * @param hex Hexadecimal string to convert to binary
         * @return Binary bytes
         */
        byte[] sodiumHex2Bin(String hex);
    }


}
