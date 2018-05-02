/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


public interface Base {
    boolean boolify(int res);
    <T> T res(int res, T object);
    String str(byte[] bs);
    boolean wrongLen(byte[] bs, int shouldBeLen);
    boolean wrongLen(int byteLength, int shouldBeLen);
    boolean wrongLen(int byteLength, long shouldBeLen);
    boolean isBetween(int num, long min, long max);
}
