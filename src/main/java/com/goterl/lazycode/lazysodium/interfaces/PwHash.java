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
        boolean cryptoPwHash(byte[] outputHash,
                             long outputHashLen,
                             byte[] password,
                             long passwordLen,
                             byte[] salt,
                             long opsLimit,
                             int memLimit,
                             int alg);

        boolean cryptoPwHashStr(byte[] outputStr,
                              byte[] password,
                              long passwordLen,
                              long opsLimit,
                              int memLimit);

        boolean cryptoPwHashStrVerify(byte[] hash, byte[] password, long passwordLen);

        boolean cryptoPwHashStrNeedsRehash(byte[] hash, long opsLimit, int memLimit);

    }

    interface Lazy {

        boolean cryptoPwHash(byte[] outputHash,
                             long outputHashLen,
                             byte[] password,
                             long passwordLen,
                             byte[] salt,
                             long opsLimit,
                             int memLimit,
                             int alg);

    }


}
