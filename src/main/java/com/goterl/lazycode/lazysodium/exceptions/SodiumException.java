/*
 * Copyright (c) Terl Tech Ltd • 03/05/18 11:04 • goterl.com
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/.
 */

package com.goterl.lazycode.lazysodium.exceptions;

public class SodiumException extends Exception {

    public SodiumException(String message) {
        super(message);
    }

    public SodiumException(String message, Throwable cause) {
        super(message, cause);
    }

    public SodiumException(Throwable cause) {
        super(cause);
    }

    protected SodiumException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
