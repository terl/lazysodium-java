/*
 * Copyright (c) Terl Tech Ltd • 07/05/18 10:34 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.structs.crypto_secretstream_xchacha20poly1305_state;

public interface SecretStream {

    int XCHACHA20POLY1305_KEYBYTES = AEAD.XCHACHA20POLY1305_IETF_KEYBYTES;

    interface Native {
        void cryptoSecretStreamXChacha20Poly1305Keygen(byte[] key);

        int cryptoSecretStreamXChacha20Poly1305InitPush(
                crypto_secretstream_xchacha20poly1305_state state,
                byte[] header,
                byte[] key
        );
    }

    interface Lazy {

    }


}
