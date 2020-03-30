package com.goterl.lazycode.lazysodium.utils;

import java.util.Base64;

public class Base64MessageEncoder implements MessageEncoder {

    @Override
    public String encode(byte[] cipher) {
        return Base64.getEncoder().encodeToString(cipher);
    }

    @Override
    public byte[] decode(String cipherText) {
        return Base64.getDecoder().decode(cipherText);
    }
}
