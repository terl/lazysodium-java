package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.LazySodium;

public class HexMessageEncoder implements MessageEncoder {

    @Override
    public String encode(byte[] cipher) {
        return LazySodium.toHex(cipher);
    }

    @Override
    public byte[] decode(String cipherText) {
        return LazySodium.toBin(cipherText);
    }
}
