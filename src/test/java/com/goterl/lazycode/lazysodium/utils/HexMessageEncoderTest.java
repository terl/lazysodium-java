package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.BaseTest;
import junit.framework.TestCase;
import org.junit.Test;

public class HexMessageEncoderTest extends BaseTest {

    @Test
    public void decodeEqualsEncode() {
        HexMessageEncoder encoder = new HexMessageEncoder();

        String cipherText = "612D6865782D656E636F6465642D737472696E67";
        byte[] cipher = encoder.decode(cipherText);

        TestCase.assertEquals(cipherText, encoder.encode(cipher));
    }
}
