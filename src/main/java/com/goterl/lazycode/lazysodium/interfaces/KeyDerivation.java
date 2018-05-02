/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 14:09 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;

import java.nio.charset.Charset;

public interface KeyDerivation {

    int
        KDF_MASTER_KEY_BYTES = 32,
        KDF_CONTEXT_BYTES = 8,
        KDF_BLAKE2B_BYTES_MIN = 16,
        KDF_BLAKE2B_BYTES_MAX = 64,
        KDF_BYTES_MIN = KDF_BLAKE2B_BYTES_MIN,
        KDF_BYTES_MAX = KDF_BLAKE2B_BYTES_MAX;

    interface Native {
        void cryptoKdfKeygen(byte[] masterKey);
        int cryptoKdfDeriveFromKey(byte[] subKey, int subKeyLen, long subKeyId, byte[] context, byte[] masterKey);
    }

    interface Lazy {
        String cryptoKdfKeygen(Charset charset);

        String cryptoKdfKeygen();

        String cryptoKdfDeriveFromKey(long subKeyId, String context, byte[] masterKey);

        String cryptoKdfDeriveFromKey(long subKeyId, String context, String masterKey);
    }
}
