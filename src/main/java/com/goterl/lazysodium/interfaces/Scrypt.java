/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;

import com.goterl.lazysodium.exceptions.SodiumException;
import com.goterl.lazysodium.utils.BaseChecker;
import com.goterl.lazysodium.utils.Constants;

public interface Scrypt {

    long SCRYPTSALSA208SHA256_BYTES_MIN = 16L,
            SCRYPTSALSA208SHA256_BYTES_MAX = Constants.SIZE_MAX,
            SCRYPTSALSA208SHA256_PASSWD_MIN = 0L,
            SCRYPTSALSA208SHA256_PASSWD_MAX = Constants.SIZE_MAX,
            SCRYPTSALSA208SHA256_SALT_BYTES = 32L,
            SCRYPTSALSA208SHA256_STRBYTES = 102L,

    SCRYPTSALSA208SHA256_OPSLIMIT_MIN = 32768L,
            SCRYPTSALSA208SHA256_OPSLIMIT_MAX = 4294967295L,
            SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 524288L,
            SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE = 33554432L,

    SCRYPTSALSA208SHA256_MEMLIMIT_MIN = 16777216L,
            SCRYPTSALSA208SHA256_MEMLIMIT_MAX = 68719476736L,
            SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216L,
            SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE = 1073741824L;



    class Checker extends BaseChecker {

        public static boolean checkOpsLimitScrypt(long opsLimit) {
            return isBetween(opsLimit, SCRYPTSALSA208SHA256_OPSLIMIT_MIN, SCRYPTSALSA208SHA256_OPSLIMIT_MAX);
        }

        public static boolean checkMemLimitScrypt(long memLimit) {
            return isBetween(memLimit, SCRYPTSALSA208SHA256_MEMLIMIT_MIN, SCRYPTSALSA208SHA256_MEMLIMIT_MAX);
        }

        public static boolean checkAllScrypt(long passwordBytesLen,
                                             long saltBytesLen,
                                             long hashLen,
                                             long opsLimit,
                                             long memLimit)
                throws SodiumException {
            if (!isBetween(passwordBytesLen, SCRYPTSALSA208SHA256_PASSWD_MIN, SCRYPTSALSA208SHA256_PASSWD_MAX)) {
                throw new SodiumException("The password provided is not the correct size.");
            }

            if (!isBetween(hashLen, SCRYPTSALSA208SHA256_BYTES_MIN, SCRYPTSALSA208SHA256_BYTES_MAX)) {
                throw new SodiumException(
                        "Please supply a hashLen greater " +
                        "than SCRYPTSALSA208SHA256_PASSWD_MIN " +
                        "but less than SCRYPTSALSA208SHA256_PASSWD_MAX");
            }

            if (!correctLen(saltBytesLen, SCRYPTSALSA208SHA256_SALT_BYTES)) {
                throw new SodiumException("The password provided is not the correct size.");
            }

            if (!checkOpsLimitScrypt(opsLimit)) {
                throw new SodiumException("The ops limit provided is not between the correct values.");
            }

            if (!checkMemLimitScrypt(memLimit)) {
                throw new SodiumException("The mem limit provided is not between the correct values.");
            }

            return true;
        }
    }



    interface Native {

        boolean cryptoPwHashScryptSalsa208Sha256(
                byte[] out,
                long outLen,
                byte[] password,
                long passwordLen,
                byte[] salt,
                long opsLimit,
                long memLimit
        );


        boolean cryptoPwHashScryptSalsa208Sha256Str(
                byte[] out,
                byte[] password,
                long passwordLen,
                long opsLimit,
                long memLimit
        );

        boolean cryptoPwHashScryptSalsa208Sha256StrVerify(
                byte[] str,
                byte[] password,
                long passwordLen
        );

        boolean cryptoPwHashScryptSalsa208Sha256Ll(
                byte[] password,
                int passwordLen,
                byte[] salt,
                int saltLen,
                long N,
                long r,
                long p,
                byte[] buf,
                int bufLen
        );

        /**
         * Checks whether the Scrypt hash needs a rehash.
         * @param hash The Scrypt hash.
         * @param opsLimit The operations limit used.
         * @param memLimit The memory limit used.
         * @return True if the Scrypt hash needs to be rehashed.
         */
        boolean cryptoPwHashScryptSalsa208Sha256StrNeedsRehash(byte[] hash, long opsLimit, long memLimit);
        
    }


    interface Lazy {
        /**
         * Hash a password using a salt.
         * @param password The password string to hash.
         * @param hashLen The length of the resulting hash. Between {@link #SCRYPTSALSA208SHA256_BYTES_MIN}
         *                and {@link #SCRYPTSALSA208SHA256_BYTES_MAX}.
         * @param salt The salt to use.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link #SCRYPTSALSA208SHA256_OPSLIMIT_MIN} and {@link #SCRYPTSALSA208SHA256_OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link #SCRYPTSALSA208SHA256_MEMLIMIT_MIN} and {@link #SCRYPTSALSA208SHA256_MEMLIMIT_MAX}.
         * @return The hashed password.
         * @throws SodiumException If the password could not be hashed.
         */
        String cryptoPwHashScryptSalsa208Sha256(
                String password,
                long hashLen,
                byte[] salt,
                long opsLimit,
                long memLimit
        ) throws SodiumException;


        /**
         * The most minimal way of hashing a given password
         * using Scrypt.
         * @param password The password string to hash.
         * @param opsLimit The number of cycles to perform whilst hashing.
         *                 Between {@link #SCRYPTSALSA208SHA256_OPSLIMIT_MIN} and {@link #SCRYPTSALSA208SHA256_OPSLIMIT_MAX}.
         * @param memLimit The amount of memory to use.
         *                 Between {@link #SCRYPTSALSA208SHA256_MEMLIMIT_MIN} and {@link #SCRYPTSALSA208SHA256_MEMLIMIT_MAX}.
         * @return The hashed password
         * @throws SodiumException If the password could not be hashed.
         */
        String cryptoPwHashScryptSalsa208Sha256Str(
                String password,
                long opsLimit,
                long memLimit
        ) throws SodiumException;


        /**
         * Verifies a string that was hashed
         * using Scrypt. This automatically adds
         * a null byte at the end if there isn't one already.
         * @param hash The hash with or without a null terminating byte.
         * @param password The password
         * @return True if the password 'unlocks' the hash.
         */
        boolean cryptoPwHashScryptSalsa208Sha256StrVerify(String hash, String password);
    }
}
