package com.goterl.lazycode.lazysodium.exceptions;

public class AEADAuthenticationException extends Exception {

    public AEADAuthenticationException() {
        super("Cannot verify the AEAD authentication tag");
    }

    public AEADAuthenticationException(String message) {
        super(message);
    }

    public AEADAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public AEADAuthenticationException(Throwable cause) {
        super(cause);
    }
}
