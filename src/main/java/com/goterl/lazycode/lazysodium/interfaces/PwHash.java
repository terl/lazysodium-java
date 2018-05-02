/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 22:35 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


public interface PwHash {

    interface Native {
        boolean sodiumPad(int paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize, int maxBufLen);
        boolean sodiumUnpad(int paddedBuffLen, char[] buf, int unpaddedBufLen, int blockSize);
    }

    interface Lazy {

    }


}
