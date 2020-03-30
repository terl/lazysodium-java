package com.goterl.lazycode.lazysodium.utils;

public interface MessageEncoder {
    String encode(byte[] cipher);
    byte[] decode(String cipherText);
}
