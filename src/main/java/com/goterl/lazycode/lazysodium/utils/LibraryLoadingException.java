package com.goterl.lazycode.lazysodium.utils;

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
