/*
 * Copyright (c) Terl Tech Ltd • 02/05/18 22:35 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.interfaces;


import com.goterl.lazycode.lazysodium.exceptions.SodiumException;
import com.goterl.lazycode.lazysodium.utils.BaseChecker;
import com.goterl.lazycode.lazysodium.utils.Constants;

import java.util.Map;

import static com.goterl.lazycode.lazysodium.utils.Constants.SIZE_MAX;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toMap;

public interface PwHash {


    int
            PWHASH_ALG_ARGON2I13 = 1,
            PWHASH_ALG_ARGON2ID13 = 2,
            PWHASH_ALG_DEFAULT = PWHASH_ALG_ARGON2ID13;


    long
            PWHASH_ARGON2ID_PASSWD_MIN = 0L,
            PWHASH_ARGON2ID_PASSWD_MAX = Constants.UNISGNED_INT,

            PWHASH_ARGON2ID_SALTBYTES = 16L,

            PWHASH_ARGON2ID_BYTES_MIN = 16L,
            PWHASH_ARGON2ID_BYTES_MAX = Constants.UNISGNED_INT,

            PWHASH_ARGON2ID_OPSLIMIT_MIN = 1L,
            PWHASH_ARGON2ID_OPSLIMIT_MAX = Constants.UNISGNED_INT,
            PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE = 2L,
            PWHASH_ARGON2ID_OPSLIMIT_MODERATE = 3L,
            PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE = 4L,

            PWHASH_ARGON2ID_MEMLIMIT_MIN = 8192L,
            PWHASH_ARGON2ID_MEMLIMIT_MAX = ((SIZE_MAX >= 4398046510080L) ? 4398046510080L : (SIZE_MAX >= 2147483648L) ? 2147483648L : 32768L),
            PWHASH_ARGON2ID_MEMLIMIT_INTERATIVE = 67108864L,
            PWHASH_ARGON2ID_MEMLIMIT_MODERATE = 268435456L,
            PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE = 1073741824L,



            // Should use these values rather than the above
            // as the above values are likely to change
            PWHASH_PASSWD_MIN = PWHASH_ARGON2ID_PASSWD_MIN,
            PWHASH_PASSWD_MAX = PWHASH_ARGON2ID_PASSWD_MAX,

            PWHASH_SALTBYTES = PWHASH_ARGON2ID_SALTBYTES,

            PWHASH_BYTES_MIN = PWHASH_ARGON2ID_BYTES_MIN,
            PWHASH_BYTES_MAX = PWHASH_ARGON2ID_BYTES_MAX,

            PWHASH_OPSLIMIT_MIN = PWHASH_ARGON2ID_OPSLIMIT_MIN,
            PWHASH_OPSLIMIT_MAX = PWHASH_ARGON2ID_OPSLIMIT_MAX,

            PWHASH_MEMLIMIT_MIN = PWHASH_ARGON2ID_MEMLIMIT_MIN,
            PWHASH_MEMLIMIT_MAX = PWHASH_ARGON2ID_MEMLIMIT_MAX;


    class Checker extends BaseChecker {
        public static boolean saltIsCorrect(long saltLen) {
            return correctLen(saltLen, PwHash.PWHASH_SALTBYTES);
        }
        public static boolean passwordIsCorrect(long len) {
            return isBetween(len, PwHash.PWHASH_BYTES_MIN, PwHash.PWHASH_BYTES_MAX);
        }
        public static boolean opsLimitIsCorrect(long ops) {
            return isBetween(ops, PwHash.PWHASH_OPSLIMIT_MIN, PwHash.PWHASH_OPSLIMIT_MAX);
        }
        public static boolean memLimitIsCorrect(long len) {
            return isBetween(len, PwHash.PWHASH_MEMLIMIT_MIN, PwHash.PWHASH_MEMLIMIT_MAX);
        }

        public static boolean checkAll(long passwordBytesLen,
                                       long saltBytesLen,
                                       long opsLimit,
                                       long memLimit)
                throws SodiumException {
            if (!PwHash.Checker.saltIsCorrect(saltBytesLen)) {
                throw new SodiumException("The salt provided is not the correct length.");
            }
            if (!PwHash.Checker.passwordIsCorrect(passwordBytesLen)) {
                throw new SodiumException("The password provided is not the correct length.");
            }
            if (!PwHash.Checker.opsLimitIsCorrect(opsLimit)) {
                throw new SodiumException("The opsLimit provided is not the correct value.");
            }
            if (!PwHash.Checker.memLimitIsCorrect(memLimit)) {
                throw new SodiumException("The memLimit provided is not the correct value.");
            }
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
                             Alg alg) throws SodiumException;

    }


    enum Alg {
        PWHASH_ALG_ARGON2I13(1),
        PWHASH_ALG_ARGON2ID13(2),
        PWHASH_ALG_DEFAULT(PWHASH_ALG_ARGON2ID13.val);

        private final int val;

        Alg(final int val) {
            this.val = val;
        }

        public int getValue() {
            return val;
        }

        public static Alg valueOf(int alg) {
            return map.get(alg);
        }

        private final static Map<Integer, Alg> map =
                stream(Alg.values()).collect(toMap(alg -> alg.val, alg -> alg));
    }


}
