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
            PWHASH_ALG_DEFAULT = PWHASH_ALG_ARGON2ID13,
            PWHASH_ARGON2ID_SALTBYTES = 16,
            PWHASH_ARGON2ID_BYTES_MIN = 16,
            PWHASH_SALTBYTES = PWHASH_ARGON2ID_SALTBYTES,

            PWHASH_ARGON2ID_STR_BYTES = 128,
            PWHASH_STR_BYTES = PWHASH_ARGON2ID_STR_BYTES;



    long
            PWHASH_ARGON2ID_PASSWD_MIN = 0L,
            PWHASH_ARGON2ID_PASSWD_MAX = Constants.UNISGNED_INT,
            PWHASH_ARGON2ID_BYTES_MAX = Constants.UNISGNED_INT,

            PWHASH_ARGON2ID_OPSLIMIT_MIN = 1L,
            PWHASH_ARGON2ID_OPSLIMIT_MAX = Constants.UNISGNED_INT,
            PWHASH_ARGON2ID_OPSLIMIT_INTERACTIVE = 2L,
            PWHASH_ARGON2ID_OPSLIMIT_MODERATE = 3L,
            PWHASH_ARGON2ID_OPSLIMIT_SENSITIVE = 4L,

            PWHASH_ARGON2ID_MEMLIMIT_MIN = 8192L,
            PWHASH_ARGON2ID_MEMLIMIT_MAX = ((SIZE_MAX >= 4398046510080L) ? 4398046510080L : (SIZE_MAX >= 2147483648L) ? 2147483648L : 32768L),
            PWHASH_ARGON2ID_MEMLIMIT_INTERACTIVE = 67108864L,
            PWHASH_ARGON2ID_MEMLIMIT_MODERATE = 268435456L,
            PWHASH_ARGON2ID_MEMLIMIT_SENSITIVE = 1073741824L,



            // Should use these values rather than the above
            // as the above values are likely to change
            PWHASH_PASSWD_MIN = PWHASH_ARGON2ID_PASSWD_MIN,
            PWHASH_PASSWD_MAX = PWHASH_ARGON2ID_PASSWD_MAX,


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
            return isBetween(len, PwHash.PWHASH_PASSWD_MIN, PwHash.PWHASH_PASSWD_MAX);
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
         * @param outputHashLen The password hash's length. Must be at least {@link PwHash#PWHASH_BYTES_MIN}.
         * @param password The password that you want to hash.
         * @param passwordLen The length of the password's bytes.
         * @param salt A salt that's randomly generated.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#PWHASH_OPSLIMIT_MIN} and {@link PwHash#PWHASH_OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#PWHASH_MEMLIMIT_MIN} and {@link PwHash#PWHASH_MEMLIMIT_MAX}.
         * @param alg The algorithm to use. Please use {@link PwHash#PWHASH_ALG_ARGON2ID13} for now.
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
         * @param outputStr An array to hold the hash. Must be at least {@link PwHash#PWHASH_STR_BYTES}.
         * @param password A password that you want to hash.
         * @param passwordLen The password's byte length.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#PWHASH_OPSLIMIT_MIN} and {@link PwHash#PWHASH_OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#PWHASH_MEMLIMIT_MIN} and {@link PwHash#PWHASH_MEMLIMIT_MAX}.
         * @return True if the hash succeeded.
         * @see #cryptoPwHashStrVerify(byte[], byte[], long)
         */
        boolean cryptoPwHashStr(byte[] outputStr,
                              byte[] password,
                              long passwordLen,
                              long opsLimit,
                              long memLimit);

        /**
         * Verifies a hashed password. If you're passing {@code password} as
         * a null terminated string use this function. However, if you're
         * using a non-null terminated string, like the one received from
         * {@link PwHash.Lazy#cryptoPwHashStrTrimmed(String, long, long)},
         * then it's recommended to disregard this function. Instead, use any verify function
         * provided in {@link PwHash.Lazy}.
         * @param hash The hash of the password.
         * @param password The password to check if it equals the hash's password.
         * @param passwordLen The checking password's length.
         * @return True if the password matches the unhashed hash.
         * @see PwHash.Lazy#cryptoPwHashStrVerify(String, String)
         */
        boolean cryptoPwHashStrVerify(byte[] hash, byte[] password, long passwordLen);


        /**
         * Check if a password verification string str matches the parameters opslimit and memlimit, and the current default algorithm.
         * @param hash The hashed password.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#PWHASH_OPSLIMIT_MIN} and {@link PwHash#PWHASH_OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#PWHASH_MEMLIMIT_MIN} and {@link PwHash#PWHASH_MEMLIMIT_MAX}.
         * @return The function returns 1 if the string appears to be correct, but doesn't match the given parameters. In that situation, applications may want to compute a new hash using the current parameters the next time the user logs in.
         *         The function returns 0 if the parameters already match the given ones.
         *         It returns -1 on error. If it happens, applications may want to compute a correct hash the next time the user logs in.
         */
        int cryptoPwHashStrNeedsRehash(byte[] hash, long opsLimit, long memLimit);

    }

    interface Lazy {

        /**
         * Hashes a given password.
         * @param password The password to hash.
         * @param salt A salt to use with the hash, generated randomly.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#PWHASH_OPSLIMIT_MIN} and {@link PwHash#PWHASH_OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#PWHASH_MEMLIMIT_MIN} and {@link PwHash#PWHASH_MEMLIMIT_MAX}.
         * @param alg The algorithm to use. Defaults to {@link PwHash#PWHASH_ALG_ARGON2ID13}.
         * @return A hash of the password in bytes.
         * @throws SodiumException If the password is too short or the opsLimit is not correct.
         */
        byte[] cryptoPwHash(byte[] password,
                            byte[] salt,
                            long opsLimit,
                            long memLimit,
                            Alg alg) throws SodiumException;


        /**
         * The most minimal way of hashing a given password.
         * We auto-generate the salt and use the default
         * hashing algorithm {@link PwHash#PWHASH_ALG_DEFAULT}.
         *
         * WARNING: This method may return null bytes at the end
         * of the returned byte array. See {@link #cryptoPwHashStrTrimmed(String, long, long)}
         * for an implementation of this method which auto-removes those null
         * bytes.
         *
         * @param password The password string to hash.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link PwHash#PWHASH_OPSLIMIT_MIN}
         *                 and {@link PwHash#PWHASH_OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link PwHash#PWHASH_MEMLIMIT_MIN}
         *                 and {@link PwHash#PWHASH_MEMLIMIT_MAX}.
         * @return Hashed password.
         * @throws SodiumException If the hashing fails.
         * @see #cryptoPwHashStrTrimmed(String, long, long)
         */
        String cryptoPwHashStr(String password,
                               long opsLimit,
                               long memLimit) throws SodiumException;

        /**
         * The most minimal way of hashing a given password.
         * We auto-generate the salt and use the default
         * hashing algorithm {@link PwHash#PWHASH_ALG_DEFAULT}.
         * This method is
         * recommended over {@link #cryptoPwHashStr(String, long, long)}
         * as this one removes all the null bytes.
         * @see #cryptoPwHashStr(String, long, long)
         */
        String cryptoPwHashStrTrimmed(String password,
                                       long opsLimit,
                                       long memLimit) throws SodiumException;

        /**
         * Verify a given password with a hash.
         * @param hash The hash
         * @param password The password
         * @return True if the password 'unlocks' the hash.
         */
        boolean cryptoPwHashStrVerify(String hash,
                                     String password);

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

        private final static Map<Integer, Alg> map =
                stream(Alg.values()).collect(toMap(alg -> alg.val, alg -> alg));
    }


}
