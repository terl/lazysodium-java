package com.goterl.lazysodium.interfaces;

import com.goterl.lazysodium.LazySodium;
import com.goterl.lazysodium.exceptions.SodiumException;
import java.math.BigInteger;
import java.util.Arrays;

public interface Ristretto255 {

    int RISTRETTO255_BYTES = 32;
    int RISTRETTO255_HASH_BYTES = 64;
    int RISTRETTO255_SCALAR_BYTES = 32;
    int RISTRETTO255_NON_REDUCED_SCALAR_BYTES = 64;
    BigInteger RISTRETTO255_L = BigInteger.valueOf(2).pow(252).add(
        new BigInteger("27742317777372353535851937790883648493", 10));

    static byte[] scalarToBytes(BigInteger n) {
        return scalarToBytes(n, true);
    }

    static byte[] scalarToBytes(BigInteger n, boolean reduced) {
        byte[] bigEndianBytes = n.toByteArray();
        int expectedCount =
            reduced ? RISTRETTO255_SCALAR_BYTES : RISTRETTO255_NON_REDUCED_SCALAR_BYTES;

        if (bigEndianBytes.length > expectedCount) {
            throw new IllegalArgumentException(
                "The scalar value is too big to be represented in " + expectedCount + " bytes");
        }

        // Convert big-endian to little-endian
        byte[] littleEndianBytes = new byte[expectedCount];

        for (int i = 0; i < bigEndianBytes.length; ++i) {
            littleEndianBytes[i] = bigEndianBytes[bigEndianBytes.length - i - 1];
        }

        return littleEndianBytes;
    }

    static BigInteger bytesToScalar(byte[] bytes) {
        byte[] temp = new byte[bytes.length];

        // Convert little-endian to big-endian
        for (int i = 0; i < bytes.length; ++i) {
            temp[bytes.length - i - 1] = bytes[i];
        }

        return new BigInteger(temp);
    }

    static byte[] pointBuffer() {
        return new byte[RISTRETTO255_BYTES];
    }

    static byte[] scalarBuffer() {
        return new byte[RISTRETTO255_SCALAR_BYTES];
    }

    interface Native {

        /**
         * Returns whether the passed bytes represent a valid Ristretto255 point.
         *
         * @param point the point to check, should be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @return true if valid
         */
        boolean cryptoCoreRistretto255IsValidPoint(byte[] point);

        /**
         * Chooses a random Ristretto255 point and puts its representation to {@code point}
         *
         * @param point the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         */
        void cryptoCoreRistretto255Random(byte[] point);

        /**
         * Maps a {@link Ristretto255#RISTRETTO255_HASH_BYTES} bytes hash to a Ristretto255 point
         * and puts its representation to {@code point}.
         *
         * @param point the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param hash  the hash, must be {@link Ristretto255#RISTRETTO255_HASH_BYTES} bytes
         * @return true if successful
         */
        boolean cryptoCoreRistretto255FromHash(byte[] point, byte[] hash);

        /**
         * Multiplies the given Ristretto255 {@code point} by the scalar {@code n} and puts the
         * representation of the result into {@code result}.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param n      the scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param point  the Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @return true if successful
         */
        boolean cryptoScalarmultRistretto255(byte[] result, byte[] n, byte[] point);

        /**
         * Multiplies the Ristretto255 base point by the scalar {@code n} and puts the
         * representation of the result into {@code result}.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param n      the scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return true if successful
         */
        boolean cryptoScalarmultRistretto255Base(byte[] result, byte[] n);

        /**
         * Adds two given Ristretto255 points {@code p} and {@code q} and puts the representation of
         * the result into {@code result}.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param p      the first Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @param q      the second Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @return true if successful
         */
        boolean cryptoCoreRistretto255Add(byte[] result, byte[] p, byte[] q);

        /**
         * Subtracts two given Ristretto255 points {@code p} and {@code q} and puts the
         * representation of the result into {@code result}.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes
         * @param p      the first Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @param q      the second Ristretto255 point, must be {@link Ristretto255#RISTRETTO255_BYTES}
         *               bytes
         * @return true if successful
         */
        boolean cryptoCoreRistretto255Sub(byte[] result, byte[] p, byte[] q);

        /**
         * Creates a random scalar value in {@code [0, l[} with {@code L} being the order of the
         * Ristretto255 group.
         *
         * @param scalar the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarRandom(byte[] scalar);

        /**
         * Reduces a possibly larger scalar value to {@code [0, l[} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param scalar the scalar to reduce, must be {@link Ristretto255#RISTRETTO255_NON_REDUCED_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarReduce(byte[] result, byte[] scalar);

        /**
         * Calculates the multiplicative inverse of the given scalar value.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param scalar the scalar to invert, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @return true if successful
         */
        boolean cryptoCoreRistretto255ScalarInvert(byte[] result, byte[] scalar);

        /**
         * Calculates the additive inverse of the given scalar value.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param scalar the scalar to negate, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarNegate(byte[] result, byte[] scalar);

        /**
         * Calculates the result R for the given scalar value such that {@code R + scalar = 1 (mod
         * L)} with {@code L} being the order of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param scalar the scalar to complement, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarComplement(byte[] result, byte[] scalar);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param x      the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param y      the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarAdd(byte[] result, byte[] x, byte[] y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param x      the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param y      the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarSub(byte[] result, byte[] x, byte[] y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param result the target array, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param x      the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @param y      the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         */
        void cryptoCoreRistretto255ScalarMul(byte[] result, byte[] x, byte[] y);
    }

    interface Lazy {

        /**
         * Returns whether the passed encoded string represents a valid Ristretto255 point.
         *
         * @param point the point to check
         * @return true if valid
         */
        boolean cryptoCoreRistretto255IsValidPoint(String point);

        /**
         * Chooses a random Ristretto255 point and returns it.
         *
         * @return a random Ristretto255 point
         */
        RistrettoPoint cryptoCoreRistretto255Random();

        /**
         * Maps a {@link Ristretto255#RISTRETTO255_HASH_BYTES} bytes hash to a {@link
         * RistrettoPoint}.
         *
         * @param hash the encoded hash
         * @return the corresponding Ristretto255 point
         */
        RistrettoPoint cryptoCoreRistretto255FromHash(String hash) throws SodiumException;

        /**
         * Maps a {@link Ristretto255#RISTRETTO255_HASH_BYTES} bytes hash to a Ristretto255 point.
         *
         * @param hash the hash, must be {@link Ristretto255#RISTRETTO255_HASH_BYTES}
         * @return the corresponding Ristretto255 point
         */
        RistrettoPoint cryptoCoreRistretto255FromHash(byte[] hash) throws SodiumException;

        /**
         * Multiplies the given Ristretto255 {@code point} by the scalar {@code n} and returns the
         * resulting point.
         *
         * @param n     the scalar
         * @param point the Ristretto255 point
         * @return the result
         */
        RistrettoPoint cryptoScalarmultRistretto255(BigInteger n, RistrettoPoint point)
            throws SodiumException;

        /**
         * Multiplies the given Ristretto255 {@code point} by the scalar {@code n} and returns the
         * resulting point.
         *
         * @param nEnc  the encoded scalar bytes, in little-endian byte order
         * @param point the Ristretto255 point
         * @return the result
         */
        RistrettoPoint cryptoScalarmultRistretto255(String nEnc, RistrettoPoint point)
            throws SodiumException;

        /**
         * Multiplies the given Ristretto255 {@code point} by the scalar {@code n} and returns the
         * resulting point.
         *
         * @param n     the scalar, must be {@link Ristretto255#RISTRETTO255_BYTES} bytes, in
         *              little-endian encoding
         * @param point the Ristretto255 point
         * @return the result
         */
        RistrettoPoint cryptoScalarmultRistretto255(byte[] n, RistrettoPoint point)
            throws SodiumException;

        /**
         * Multiplies the Ristretto255 base point by the scalar {@code n} and returns the result.
         *
         * @param n the scalar
         * @return the result
         */
        RistrettoPoint cryptoScalarmultRistretto255Base(BigInteger n) throws SodiumException;

        /**
         * Multiplies the Ristretto255 base point by the scalar {@code n} and returns the result.
         *
         * @param nEnc the encoded scalar, in little-endian byte order
         * @return the result
         */
        RistrettoPoint cryptoScalarmultRistretto255Base(String nEnc) throws SodiumException;

        /**
         * Multiplies the Ristretto255 base point by the scalar {@code n} and returns the result.
         *
         * @param n the scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes, in
         *          little-endian encoding
         * @return the result
         */
        RistrettoPoint cryptoScalarmultRistretto255Base(byte[] n) throws SodiumException;

        /**
         * Adds two given Ristretto255 points {@code p} and {@code q} and returns the result.
         *
         * @param p the first Ristretto255 point
         * @param q the second Ristretto255 point
         * @return the sum
         */
        RistrettoPoint cryptoCoreRistretto255Add(RistrettoPoint p, RistrettoPoint q)
            throws SodiumException;

        /**
         * Subtracts two given Ristretto255 points {@code p} and {@code q} and returns the result.
         *
         * @param p the first Ristretto255 point
         * @param q the second Ristretto255 point
         * @return the difference
         */
        RistrettoPoint cryptoCoreRistretto255Sub(RistrettoPoint p, RistrettoPoint q)
            throws SodiumException;

        /**
         * Creates a random scalar value in {@code [0, l[} with {@code L} being the order of the
         * Ristretto255 group.
         *
         * @return the random scalar value
         */
        BigInteger cryptoCoreRistretto255ScalarRandom();

        /**
         * Reduces a possibly larger scalar value to {@code [0, l[} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param scalar the scalar to reduce
         * @return the reduced scalar
         */
        BigInteger cryptoCoreRistretto255ScalarReduce(BigInteger scalar);

        /**
         * Reduces a possibly larger scalar value to {@code [0, l[} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param scalarEnc the encoded scalar to reduce
         * @return the reduced scalar
         */
        BigInteger cryptoCoreRistretto255ScalarReduce(String scalarEnc);

        /**
         * Reduces a possibly larger scalar value to {@code [0, L[} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param scalar the scalar to reduce, must be {@link Ristretto255#RISTRETTO255_NON_REDUCED_SCALAR_BYTES}
         *               bytes
         * @return the reduced scalar
         */
        BigInteger cryptoCoreRistretto255ScalarReduce(byte[] scalar);

        /**
         * Calculates the multiplicative inverse of the given scalar value.
         *
         * @param scalar the scalar to invert
         * @return the multiplicative inverse
         */
        BigInteger cryptoCoreRistretto255ScalarInvert(BigInteger scalar) throws SodiumException;

        /**
         * Calculates the multiplicative inverse of the given scalar value.
         *
         * @param scalarEnc the encoded scalar to invert
         * @return the multiplicative inverse
         */
        BigInteger cryptoCoreRistretto255ScalarInvert(String scalarEnc) throws SodiumException;

        /**
         * Calculates the multiplicative inverse of the given scalar value.
         *
         * @param scalar the scalar to invert, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @return the multiplicative inverse
         */
        BigInteger cryptoCoreRistretto255ScalarInvert(byte[] scalar) throws SodiumException;

        /**
         * Calculates the additive inverse of the given scalar value.
         *
         * @param scalar the scalar to negate
         * @return the additive inverse
         */
        BigInteger cryptoCoreRistretto255ScalarNegate(BigInteger scalar);

        /**
         * Calculates the additive inverse of the given scalar value.
         *
         * @param scalarEnc the encoded scalar to negate
         * @return the additive inverse
         */
        BigInteger cryptoCoreRistretto255ScalarNegate(String scalarEnc);

        /**
         * Calculates the additive inverse of the given scalar value.
         *
         * @param scalar the scalar to negate, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @return the additive inverse
         */
        BigInteger cryptoCoreRistretto255ScalarNegate(byte[] scalar);

        /**
         * Calculates the result R for the given scalar value such that {@code R + scalar = 1 (mod
         * L)} with {@code L} being the order of the Ristretto255 group.
         *
         * @param scalar the scalar to complement
         * @return the complement
         */
        BigInteger cryptoCoreRistretto255ScalarComplement(BigInteger scalar);

        /**
         * Calculates the result R for the given scalar value such that {@code R + scalar = 1 (mod
         * L)} with {@code L} being the order of the Ristretto255 group.
         *
         * @param scalarEnc the encoded scalar to complement
         * @return the complement
         */
        BigInteger cryptoCoreRistretto255ScalarComplement(String scalarEnc);

        /**
         * Calculates the result R for the given scalar value such that {@code R + scalar = 1 (mod
         * L)} with {@code L} being the order of the Ristretto255 group.
         *
         * @param scalar the scalar to complement, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES}
         *               bytes
         * @return the complement
         */
        BigInteger cryptoCoreRistretto255ScalarComplement(byte[] scalar);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, BigInteger y);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar (encoded)
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, String y);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(String x, BigInteger y);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar (encoded)
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(String x, String y);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(String x, byte[] y);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar (encoded)
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, String y);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(BigInteger x, byte[] y);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, BigInteger y);

        /**
         * Adds two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the order
         * of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the sum
         */
        BigInteger cryptoCoreRistretto255ScalarAdd(byte[] x, byte[] y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, BigInteger y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar (encoded)
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, String y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(String x, BigInteger y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar (encoded)
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(String x, String y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(String x, byte[] y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar (encoded)
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, String y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(BigInteger x, byte[] y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, BigInteger y);

        /**
         * Subtracts two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the difference
         */
        BigInteger cryptoCoreRistretto255ScalarSub(byte[] x, byte[] y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, BigInteger y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar (encoded)
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, String y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(String x, BigInteger y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar (encoded)
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(String x, String y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar (encoded)
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(String x, byte[] y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar (encoded)
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, String y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(BigInteger x, byte[] y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, BigInteger y);

        /**
         * Multiplies two scalars {@code x} and {@code y} modulo {@code L} with {@code L} being the
         * order of the Ristretto255 group.
         *
         * @param x the first scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @param y the second scalar, must be {@link Ristretto255#RISTRETTO255_SCALAR_BYTES} bytes
         * @return the product
         */
        BigInteger cryptoCoreRistretto255ScalarMul(byte[] x, byte[] y);
    }

    class Checker {
        private Checker() {}

        public static void ensurePointFits(byte[] point) {
            if (point == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as target arrays");
            }

            if (point.length < RISTRETTO255_BYTES) {
                throw new IllegalArgumentException(
                    "To hold a Ristretto255 point, the array must be "
                        + RISTRETTO255_BYTES
                        + " bytes in size");
            }
        }

        public static void ensureScalarFits(byte[] scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as target arrays");
            }

            if (scalar.length < RISTRETTO255_SCALAR_BYTES) {
                throw new IllegalArgumentException(
                    "To hold a Ristretto255 scalar, the array must be "
                        + RISTRETTO255_SCALAR_BYTES
                        + " bytes in size");
            }
        }

        public static void checkPoint(byte[] point) {
            if (point == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as Ristretto255 points");
            }

            if (point.length != RISTRETTO255_BYTES) {
                throw new IllegalArgumentException("A Ristretto255 point must be "
                                                       + RISTRETTO255_BYTES
                                                       + " bytes in size");
            }
        }

        public static void checkHash(byte[] hash) {
            if (hash == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as Ristretto255 hashes");
            }

            if (hash.length != RISTRETTO255_HASH_BYTES) {
                throw new IllegalArgumentException("A hash for use with Ristretto255 must be "
                                                       + RISTRETTO255_HASH_BYTES
                                                       + " bytes in size");
            }
        }

        public static void checkScalar(byte[] scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as Ristretto255 scalars");
            }

            if (scalar.length != RISTRETTO255_SCALAR_BYTES) {
                throw new IllegalArgumentException("A Ristretto255 scalar must be "
                                                       + RISTRETTO255_SCALAR_BYTES
                                                       + " bytes in size");
            }
        }

        public static void checkNonReducedScalar(byte[] scalar) {
            if (scalar == null) {
                throw new IllegalArgumentException(
                    "Null pointers are not allowed as non-reduced Ristretto255 scalars");
            }

            if (scalar.length != RISTRETTO255_NON_REDUCED_SCALAR_BYTES) {
                throw new IllegalArgumentException("A non-reduced Ristretto255 scalar must be "
                                                       + RISTRETTO255_NON_REDUCED_SCALAR_BYTES
                                                       + " bytes in size");
            }
        }
    }

    final class RistrettoPoint {

        private final LazySodium ls;
        private final byte[] repr;

        private RistrettoPoint(LazySodium ls, byte[] repr) {
            if (repr == null || !ls.cryptoCoreRistretto255IsValidPoint(repr)) {
                throw new IllegalArgumentException("The passed point is invalid");
            }

            this.repr = repr;
            this.ls = ls;
        }

        private RistrettoPoint(LazySodium ls, String encoded) {
            this(ls, ls.decodeFromString(encoded));
        }

        @Override
        public String toString() {
            return encode();
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }

            if (!(o instanceof RistrettoPoint)) {
                return false;
            }

            RistrettoPoint that = (RistrettoPoint) o;
            return Arrays.equals(this.repr, that.repr);
        }

        @Override
        public int hashCode() {
            return Arrays.hashCode(repr);
        }

        /**
         * Returns the hexadecimal notation of this point's canonical encoding.
         *
         * @return the point in hexadecimal notation
         */
        public String toHex() {
            return ls.toHexStr(repr);
        }

        /**
         * Returns this point's canonical encoding.
         *
         * @return the point
         */
        public byte[] toBytes() {
            return repr;
        }

        /**
         * Encodes the point using the {@link LazySodium}'s associated {@link MessageEncoder}.
         * @return the encoded point
         */
        public String encode() {
            return ls.encodeToString(repr);
        }

        /**
         * Multiplies this point by a given scalar.
         *
         * @param n the scalar to multiply by
         * @return the multiplied point
         * @throws SodiumException if the result is zero
         */
        public RistrettoPoint scalarMult(BigInteger n) throws SodiumException {
            return ls.cryptoScalarmultRistretto255(n, this);
        }

        /**
         * Multiplies this point by a given scalar.
         *
         * @param n the scalar to multiply by
         * @return the multiplied point
         * @throws SodiumException if the result is zero
         */
        public RistrettoPoint times(BigInteger n) throws SodiumException {
            return scalarMult(n);
        }

        /**
         * Adds the given point to this point. Addition is commutative.
         *
         * @param other the point to add
         * @return the sum of both points
         * @throws SodiumException when the operation failed
         */
        public RistrettoPoint plus(RistrettoPoint other) throws SodiumException {
            return ls.cryptoCoreRistretto255Add(this, other);
        }

        /**
         * Subtracts the given point from this point.
         *
         * @param other the point to subtract
         * @return the difference of both points.
         * @throws SodiumException when the operation failed
         */
        public RistrettoPoint minus(RistrettoPoint other) throws SodiumException {
            return ls.cryptoCoreRistretto255Sub(this, other);
        }

        /**
         * Returns the additive inverse of this point. This is equivalent to {@code 0 - p} where 0
         * denotes the additive identity.
         *
         * @return the additive inverse
         * @throws SodiumException when the operation failed.
         */
        public RistrettoPoint negate() throws SodiumException {
            return zero(ls).minus(this);
        }

        /**
         * Returns the zero element (identity element) of the Ristretto255 group.
         *
         * @param ls the {@link LazySodium} instance
         * @return the identity element of Ristretto255
         */
        public static RistrettoPoint zero(LazySodium ls) {
            return fromBytes(ls, pointBuffer());
        }

        /**
         * Returns a random element of the Ristretto255 group.
         *
         * @param ls the {@link LazySodium} instance
         * @return a random element of Ristretto255
         */
        public static RistrettoPoint random(LazySodium ls) {
            return ls.cryptoCoreRistretto255Random();
        }

        /**
         * Returns the base point of the Ristretto255 group.
         *
         * @param ls the {@link LazySodium} instance
         * @return the base point of Ristretto255
         */
        public static RistrettoPoint base(LazySodium ls) throws SodiumException {
            return ls.cryptoScalarmultRistretto255Base(BigInteger.ONE);
        }

        /**
         * Creates a new {@link RistrettoPoint} from the hexadecimal representation. The hexadecimal
         * representation must be a valid canonical encoding.
         *
         * @param ls  the {@link LazySodium} instance
         * @param hex the Ristretto255 canonical encoding in hexadecimal notation
         * @return the corresponding {@link RistrettoPoint}
         */
        public static RistrettoPoint fromHex(LazySodium ls, String hex) {
            return new RistrettoPoint(ls, ls.toBinary(hex));
        }

        /**
         * Creates a new {@link RistrettoPoint} from the encoded representation, using the
         * {@link LazySodium}'s associated {@link MessageEncoder}. The decoded bytes must be a valid
         * canonical encoding.
         *
         * @param ls the {@link LazySodium} instance
         * @param encoded the encoded Ristretto255 point
         * @return the corresponding {@link RistrettoPoint}
         */
        public static RistrettoPoint fromString(LazySodium ls, String encoded) {
            return new RistrettoPoint(ls, encoded);
        }

        /**
         * Creates a new {@link RistrettoPoint} from the binary representation. The binary
         * representation must be a valid canonical encoding.
         *
         * @param ls    the {@link LazySodium} instance
         * @param bytes the Ristretto255 canonical encoding
         * @return the corresponding {@link RistrettoPoint}
         */
        public static RistrettoPoint fromBytes(LazySodium ls, byte[] bytes) {
            return new RistrettoPoint(ls, bytes);
        }

        /**
         * Maps the encoded input to a {@link RistrettoPoint}, using the {@link LazySodium}'s
         * associated {@link MessageEncoder}. The resulting bytes are hashed using SHA-512 and
         * mapped to the Ristretto 255 group, using {@code crypto_code_ristretto255_from_hash},
         * i.e. the standard hash-to-group algorithm.
         *
         * @param ls the {@link LazySodium} instance
         * @param encodedInput the encoded bytes
         * @return the mapped {@link RistrettoPoint}
         * @throws SodiumException if the mapping failed
         */
        public static RistrettoPoint hashToPoint(LazySodium ls, String encodedInput)
            throws SodiumException {
            return hashToPoint(ls, ls.decodeFromString(encodedInput));
        }

        /**
         * Maps the input to a {@link RistrettoPoint}, by calculating the SHA-512 hash and
         * mapping it to the Ristretto 255 group, using {@code crypto_code_ristretto255_from_hash},
         * i.e. the standard hash-to-group algorithm.
         *
         * @param ls the {@link LazySodium} instance
         * @param input the input bytes
         * @return the mapped {@link RistrettoPoint}
         * @throws SodiumException if the mapping failed
         */
        public static RistrettoPoint hashToPoint(LazySodium ls, byte[] input)
            throws SodiumException {
            byte[] hash = new byte[Hash.SHA512_BYTES];
            ls.cryptoHashSha512(hash, input, input.length);

            return ls.cryptoCoreRistretto255FromHash(hash);
        }
    }
}
