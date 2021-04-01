/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


public interface Helpers {

    interface Native {
        int sodiumInit();
    }

    interface Lazy {

        /**
         * Binary to hexadecimal. This method does not null terminate strings.
         * @param bin The binary bytes you want to convert to a string.
         * @return A hexadecimal string solely made up of the characters 0123456789ABCDEF.
         */
        String sodiumBin2Hex(byte[] bin);

        /**
         * Hexadecimal to binary. Does not null terminate the binary
         * array.
         * @param hex Hexadecimal string (a string that's
         *            made up of the characters 0123456789ABCDEF)
         *            to convert to a binary array.
         * @return Binary byte array.
         */
        byte[] sodiumHex2Bin(String hex);


    }


}
