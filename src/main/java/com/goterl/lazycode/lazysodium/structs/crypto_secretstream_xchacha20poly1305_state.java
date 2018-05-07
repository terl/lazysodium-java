/*
 * Copyright (c) Terl Tech Ltd • 07/05/18 11:55 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.structs;

import com.sun.jna.Structure;

import java.util.Arrays;
import java.util.List;

public class crypto_secretstream_xchacha20poly1305_state extends Structure {

    public static class ByReference extends crypto_secretstream_xchacha20poly1305_state implements Structure.ByReference { }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("k", "pad");
    }

    public byte[] k;
    public byte[] pad;

}
