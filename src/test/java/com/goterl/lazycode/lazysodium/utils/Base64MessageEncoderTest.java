package com.goterl.lazycode.lazysodium.utils;

import com.goterl.lazycode.lazysodium.BaseTest;
import junit.framework.TestCase;
import org.junit.Test;

public class Base64MessageEncoderTest extends BaseTest {

    @Test
    public void decodeEqualsEncode() {
        Base64MessageEncoder encoder = new Base64MessageEncoder();

        String cipherText = "YS1iYXNlNjQtZW5jb2RlZC1zdHJpbmcK";
        byte[] cipher = encoder.decode(cipherText);

        TestCase.assertEquals(cipherText, encoder.encode(cipher));
    }
}
