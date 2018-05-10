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

import java.util.HashMap;
import java.util.Map;

import static com.goterl.lazycode.lazysodium.utils.Constants.SIZE_MAX;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toMap;

public interface PwHash {


    int ALG_ARGON2I13 = 1,
        ALG_ARGON2ID13 = 2,
        ALG_DEFAULT = ALG_ARGON2ID13,
        ARGON2ID_SALTBYTES = 16,
        ARGON2ID_BYTES_MIN = 16,
        SALTBYTES = ARGON2ID_SALTBYTES,

        ARGON2ID_STR_BYTES = 128,
        STR_BYTES = ARGON2ID_STR_BYTES;



    long ARGON2ID_PASSWD_MIN = 0L,
        ARGON2ID_PASSWD_MAX = Constants.UNISGNED_INT,
        ARGON2ID_BYTES_MAX = Constants.UNISGNED_INT,

        ARGON2ID_OPSLIMIT_MIN = 1L,
        ARGON2ID_OPSLIMIT_MAX = Constants.UNISGNED_INT,
        ARGON2ID_OPSLIMIT_INTERACTIVE = 2L,
        ARGON2ID_OPSLIMIT_MODERATE = 3L,
        ARGON2ID_OPSLIMIT_SENSITIVE = 4L,

        ARGON2ID_MEMLIMIT_MIN = 8192L,
        ARGON2ID_MEMLIMIT_MAX = ((SIZE_MAX >= 4398046510080L) ? 4398046510080L : (SIZE_MAX >= 2147483648L) ? 2147483648L : 32768L),
        ARGON2ID_MEMLIMIT_INTERACTIVE = 67108864L,
        ARGON2ID_MEMLIMIT_MODERATE = 268435456L,
        ARGON2ID_MEMLIMIT_SENSITIVE = 1073741824L,


        // Should use these values rather than the above
        // as the above values are likely to change
        PASSWD_MIN = ARGON2ID_PASSWD_MIN,
        PASSWD_MAX = ARGON2ID_PASSWD_MAX,

        BYTES_MIN = ARGON2ID_BYTES_MIN,
        BYTES_MAX = ARGON2ID_BYTES_MAX,

        OPSLIMIT_MIN = ARGON2ID_OPSLIMIT_MIN,
        OPSLIMIT_MAX = ARGON2ID_OPSLIMIT_MAX,

        MEMLIMIT_MIN = ARGON2ID_MEMLIMIT_MIN,
        MEMLIMIT_MAX = ARGON2ID_MEMLIMIT_MAX;



    class Checker extends BaseChecker {
        public static boolean saltIsCorrect(long saltLen) {
            return correctLen(saltLen, PwHash.SALTBYTES);
        }
        public static boolean passwordIsCorrect(long len) {
            return isBetween(len, PwHash.PASSWD_MIN, PwHash.PASSWD_MAX);
        }
        public static boolean opsLimitIsCorrect(long ops) {
            return isBetween(ops, PwHash.OPSLIMIT_MIN, PwHash.OPSLIMIT_MAX);
        }
        public static boolean memLimitIsCorrect(long len) {
            return isBetween(len, PwHash.MEMLIMIT_MIN, PwHash.MEMLIMIT_MAX);
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
            return true;
        }
    }

    interface Native {

        /**
         * Based on a password you provide, hash that
         * password and put the output into {@code outputHash}.
         *
         * Take note that the output of this does NOT output a traditional
         * Argon 2 string as the underlying native implementation calls argon2id_hash_raw
         * instead of argon2id_hash_encoded. If you want an Argon 2 encoded string please refer
         * to {@link #cryptoPwHashStr(byte[], byte[], long, long, long)} instead.
         * @param outputHash Where to store the resulting password hash.
         * @param outputHashLen The password hash's length. Must be at least {@link PwHash#BYTES_MIN}.
         * @param password The password that you want to hash.
         * @param passwordLen The length of the password's bytes.
         * @param salt A salt that's randomly generated.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN} and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN} and {@link PwHash#MEMLIMIT_MAX}.
         * @param alg The algorithm to use. Please use {@link PwHash#ALG_ARGON2ID13} for now.
         * @return True if the hash succeeded.
         */
        boolean cryptoPwHash(byte[] outputHash,
                             long outputHashLen,
                             byte[] password,
                             long passwordLen,
                             byte[] salt,
                             long opsLimit,
                             long memLimit,
                             Alg alg);

        /**
         * Hashes a password and stores it into an array. The output is
         * an ASCII encoded string in a byte array.
         * @param outputStr An array to hold the hash. Must be at least {@link PwHash#STR_BYTES}.
         * @param password A password that you want to hash.
         * @param passwordLen The password's byte length.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN} and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN} and {@link PwHash#MEMLIMIT_MAX}.
         * @return True if the hash succeeded.
         * @see #cryptoPwHashStrVerify(byte[], byte[], long)
         */
        boolean cryptoPwHashStr(byte[] outputStr,
                              byte[] password,
                              long passwordLen,
                              long opsLimit,
                              long memLimit);

        /**
         * Verifies a hashed password.
         * @param hash The hash of the password.
         * @param password The password to check if it equals the hash's password.
         * @param passwordLen The checking password's length.
         * @return True if the password matches the unhashed hash.
         */
        boolean cryptoPwHashStrVerify(byte[] hash, byte[] password, long passwordLen);


        boolean cryptoPwHashStrNeedsRehash(byte[] hash, long opsLimit, long memLimit);

    }

    interface Lazy {

        /**
         * Hashes a given password.
         * @param cryptoPwHashLen The hash size that you want.
         *                     Anything between {@link #BYTES_MIN} and {@link #BYTES_MAX}
         * @param password The password to hash.
         * @param salt A salt to use with the hash, generated randomly.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN} and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN} and {@link PwHash#MEMLIMIT_MAX}.
         * @param alg The algorithm to use. Defaults to {@link PwHash#ALG_ARGON2ID13}.
         * @return A hash of the password in bytes.
         * @throws SodiumException If the password is too short or the opsLimit is not correct.
         */
        byte[] cryptoPwHash(int cryptoPwHashLen,
                            byte[] password,
                            byte[] salt,
                            long opsLimit,
                            long memLimit,
                            Alg alg) throws SodiumException;


        /**
         * The most minimal way of hashing a given password.
         * We auto-generate the salt and use the default
         * hashing algorithm {@link PwHash#ALG_DEFAULT}.
         * @param password The password string to hash.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN}
         *                 and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN}
         *                 and {@link PwHash#MEMLIMIT_MAX}.
         * @return
         * @throws SodiumException
         */
        String cryptoPwHashStr(String password,
                               long opsLimit,
                               long memLimit) throws SodiumException;

        /**
         * Hashes a string and removes all the null bytes. Uses the
         * hashing algorithm {@link PwHash#ALG_DEFAULT}.
         * @param password The password string to hash.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#OPSLIMIT_MIN}
         *                 and {@link PwHash#OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#MEMLIMIT_MIN}
         *                 and {@link PwHash#MEMLIMIT_MAX}.
         * @return
         * @throws SodiumException
         */
        String cryptoPwHashStrRemoveNulls(String password,
                                           long opsLimit,
                                           long memLimit) throws SodiumException;

    }


    enum Alg {
        PWHASH_ALG_ARGON2I13(1),
        PWHASH_ALG_ARGON2ID13(2);

        private final int val;

        Alg(final int val) {
            this.val = val;
        }

        public int getValue() {
            return val;
        }

        public static Alg getDefault() {
            return PWHASH_ALG_ARGON2ID13;
        }

        public static Alg valueOf(int alg) {
            return map.get(alg);
        }

        private final static Map<Integer, Alg> map = getMap();

        private static Map<Integer, Alg> getMap() {
            Map<Integer, Alg> map = new HashMap<>();
            for (Alg alg : Alg.values()) {
                map.put(alg.val, alg);
            }
            return map;
        }
    }


}
