/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 22:35 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.utils.Constants;

import static com.goterl.lazycode.lazysodium.utils.Constants.SIZE_MAX;

public interface PwHash {

    long
            PWHASH_ARGON2ID_PASSWD_MIN = 0L,
            PWHASH_ARGON2ID_PASSWD_MAX = Constants.UNISGNED_INT,

            PWHASH_ARGON2ID_SALTBYTES = 16L,

            PWHASH_ARGON2ID_BYTES_MIN = 16L,
            PWHASH_ARGON2ID_BYTES_MAX = Constants.UNISGNED_INT,

            PWHASH_ARGON2ID_OPSLIMIT_MIN = 1L,
            PWHASH_ARGON2ID_OPSLIMIT_MAX = Constants.UNISGNED_INT,


            PWHASH_ARGON2ID_MEMLIMIT_MIN = 8192L,
            PWHASH_ARGON2ID_MEMLIMIT_MAX = ((SIZE_MAX >= 4398046510080L) ? 4398046510080L : (SIZE_MAX >= 2147483648L) ? 2147483648L : 32768L),

            PWHASH_PASSWD_MIN = PWHASH_ARGON2ID_PASSWD_MIN,
            PWHASH_PASSWD_MAX = PWHASH_ARGON2ID_PASSWD_MAX,

            PWHASH_SALTBYTES = PWHASH_ARGON2ID_SALTBYTES,

            PWHASH_BYTES_MIN = PWHASH_ARGON2ID_BYTES_MIN,
            PWHASH_BYTES_MAX = PWHASH_ARGON2ID_BYTES_MAX;


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

        byte[] cryptoPwHash(byte[] salt,
                             long opsLimit,
                             int memLimit,
                             int alg);

    }


}
