/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.utils;

import java.nio.charset.Charset;


public class DetachedDecrypt extends Detached {

    byte[] message;
    Charset charset;

    public DetachedDecrypt(byte[] message, byte[] mac) {
        super(mac);
        this.message = message;
        this.charset = Charset.forName("UTF-8");
    }

    public DetachedDecrypt(byte[] message, byte[] mac, Charset charset) {
        super(mac);
        this.message = message;
        this.charset = charset;
    }


    public byte[] getMessage() {
        return message;
    }

    public String getMessageString(Charset charset) {
        return new String(getMessage(), charset);
    }

    public String getMessageString() {
        return new String(getMessage(), charset);
    }

}
