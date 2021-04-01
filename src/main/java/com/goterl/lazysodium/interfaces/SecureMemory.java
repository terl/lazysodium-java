/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.interfaces;


import com.sun.jna.Pointer;

public interface SecureMemory {


    interface Native {

        /**
         * The sodium_memzero() function tries to effectively zero len bytes starting at pnt,
         * even if optimizations are being applied to the code.
         * @param pnt The byte array to zero out.
         * @param len How many bytes to zero out.
         * @return True if zeroed
         */
        boolean sodiumMemZero(byte[] pnt, int len);

        /**
         * Locks at least len bytes of memory from the array.
         * This can help avoid swapping sensitive data to disk.
         * @param array Array to lock.
         * @param len Number of bytes to lock.
         * @return True if locked, false otherwise.
         */
        boolean sodiumMLock(byte[] array, int len);

        /**
         * Unlocks at least len bytes of memory from the array.
         * @param array Array to unlock.
         * @param len Number of bytes to unlock.
         * @return True if unlocked, false otherwise.
         */
        boolean sodiumMUnlock(byte[] array, int len);

        /**
         * Returns a pointer from which exactly
         * size contiguous bytes of memory can be accessed.
         * @param size The size of the byte array to allocate.
         * @return A Pointer to the byte array.
         */
        Pointer sodiumMalloc(int size);

        /**
         * Returns a pointer from which
         * count objects that are size bytes of memory each can be accessed.
         * It provides the same guarantees as {@link #sodiumMalloc(int)} but
         * also protects against arithmetic overflows when count * size exceeds SIZE_MAX.
         * @param count Number of objects
         * @param size Size of those objects
         * @return A Pointer to the resulting array.
         */
        Pointer sodiumAllocArray(int count, int size);

        /**
         * Unlocks and deallocates memory allocated using {@link #sodiumMalloc(int)} or {@link #sodiumAllocArray(int, int)}}.
         * @param p The pointer to which an array shall be freed.
         */
        void sodiumFree(Pointer p);

        /**
         * Makes a region allocated using {@link #sodiumMalloc(int)} or {@link #sodiumAllocArray(int, int)}}
         * inaccessible. It cannot be read or written, but the data is preserved.
         * @param ptr The pointer to a region to decline access to.
         * @return True if operation completed successfully.
         */
        boolean sodiumMProtectNoAccess(Pointer ptr);

        /**
         * Marks a region allocated using {@link #sodiumMalloc(int)} or {@link #sodiumAllocArray(int, int)}}
         * as read-only.
         * Attempting to modify the data will cause the process to terminate.
         * @param ptr Pointer to the region.
         * @return True if operation completed successfully.
         */
        boolean sodiumMProtectReadOnly(Pointer ptr);

        /**
         * Marks a region allocated using {@link #sodiumMalloc(int)} or {@link #sodiumAllocArray(int, int)}}
         * as readable and writable, after having been protected using
         * {@link #sodiumMProtectReadOnly(Pointer)} or {@link #sodiumMProtectNoAccess(Pointer)}}/
         * @param ptr Pointer to the region.
         * @return True if operation completed successfully.
         */
        boolean sodiumMProtectReadWrite(Pointer ptr);

    }


    // There are no Lazy functions as the above
    // functions are very low level by their nature
    interface Lazy {

    }


}
