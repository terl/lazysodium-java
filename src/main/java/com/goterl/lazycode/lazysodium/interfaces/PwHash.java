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

    int
            PWHASH_ALG_DEFAULT = 0,
            PWHASH_ALG_ARGON2I13 = 1,
            PWHASH_ALG_ARGON2ID13 = 2;

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
            PWHASH_BYTES_MAX = PWHASH_ARGON2ID_BYTES_MAX,

            PWHASH_OPSLIMIT_MIN = PWHASH_ARGON2ID_OPSLIMIT_MIN,
            PWHASH_OPSLIMIT_MAX = PWHASH_ARGON2ID_OPSLIMIT_MAX,

            PWHASH_MEMLIMIT_MIN = PWHASH_ARGON2ID_MEMLIMIT_MIN,
            PWHASH_MEMLIMIT_MAX = PWHASH_ARGON2ID_MEMLIMIT_MAX;


    class Checker {
        public static boolean passwordIsWrongLen(long len) {
            return PwHash.PWHASH_BYTES_MIN <= len && PwHash.PWHASH_BYTES_MAX >= len;
        }
        public static boolean opsLimitIsWrongLen(long ops) {
            return PwHash.PWHASH_OPSLIMIT_MIN <= ops && PwHash.PWHASH_OPSLIMIT_MAX >= ops;
        }
        public static boolean memLimitIsWrongLen(long len) {
            return PwHash.PWHASH_MEMLIMIT_MAX <= len && PwHash.PWHASH_MEMLIMIT_MAX >= len;
        }
    }

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

        Byte[] cryptoPwHash(byte[] password,
                            byte[] salt,
                             long opsLimit,
                             int memLimit,
                             int alg);

    }


}
