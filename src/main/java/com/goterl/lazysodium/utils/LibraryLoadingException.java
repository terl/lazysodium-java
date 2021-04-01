/*
 * Copyright (c) Terl Tech Ltd • 01/04/2021, 12:31 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazysodium.utils;

/**
 * Indicates a failure to load the required library.
 */
public class LibraryLoadingException extends RuntimeException {

    public LibraryLoadingException(String message) {
        super(message);
    }

    public LibraryLoadingException(String message, Throwable cause) {
        super(message, cause);
    }
}
