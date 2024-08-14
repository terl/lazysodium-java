/*
 * Copyright (c) Terl Tech Ltd  • 04/04/2021, 00:07 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.codevasp.lazysodium.utils;

/**
 * Indicates a failure to load the required library.
 */
public class ResourceLoaderException extends RuntimeException {

    public ResourceLoaderException(String message) {
        super(message);
    }

    public ResourceLoaderException(String message, Throwable cause) {
        super(message, cause);
    }
}