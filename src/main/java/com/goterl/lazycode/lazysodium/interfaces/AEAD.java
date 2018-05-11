/*
 * Copyright (c) Terl Tech Ltd • 07/05/18 13:07 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


public interface AEAD {


    // REGULAR CHACHA

    int CHACHA20POLY1305_KEYBYTES = 32,
        CHACHA20POLY1305_NPUBBYTES = 8,
        CHACHA20POLY1305_ABYTES = 16;



    // IETF CHACHA

    int CHACHA20POLY1305_IETF_ABYTES = 16,
        CHACHA20POLY1305_IETF_KEYBYTES = 32,
        CHACHA20POLY1305_IETF_NPUBBYTES = 12;



    // This is XCHACHA not CHACHA.

    int XCHACHA20POLY1305_IETF_KEYBYTES = 32,
        XCHACHA20POLY1305_IETF_ABYTES = 16,
        XCHACHA20POLY1305_IETF_NPUBBYTES = 24;





}
