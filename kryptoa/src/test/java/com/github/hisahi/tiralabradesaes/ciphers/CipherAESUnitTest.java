package com.github.hisahi.tiralabradesaes.ciphers;

import com.github.hisahi.tiralabradesaes.Utils;
import java.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CipherAESUnitTest {
    
    private CipherAES aes;
    
    public CipherAESUnitTest() {
    }
    
    @Before
    public void setUp() {
        aes = new CipherAES();
    }
    
    @After
    public void tearDown() {
        try {
            aes.finish();
        } catch (IllegalStateException ex) {}
    }

    @Test
    public void testEncrypt128() {
        aes.initEncrypt(Utils.convertToHex("000102030405060708090a0b0c0d0e0f"));
        byte[] res = aes.process(Utils.convertToHex("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertToHex("69c4e0d86a7b0430d8cdb78070b4c55a"), res);
    }

    @Test
    public void testEncrypt192() {
        aes.initEncrypt(Utils.convertToHex("aa9dca3ba4de72155c652ae17cfa6926cfd12addbb2b212c"));
        byte[] res = aes.process(Utils.convertToHex("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertToHex("a174c3f09dcac31edc78ed7c5b816a75"), res);
    }

    @Test
    public void testEncrypt256() {
        aes.initEncrypt(Utils.convertToHex("b6d40ab01a80415ae8ee56bc7998ed12ac017d3fd5433373c578fbb117906b18"));
        byte[] res = aes.process(Utils.convertToHex("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertToHex("305ac3d618fcf837b25772f5720b4aad"), res);
    }

    @Test
    public void testDecrypt128() {
    }

    @Test
    public void testDecrypt192() {
    }

    @Test
    public void testDecrypt256() {
    }

    @Test
    public void testEncryptAndDecrypt128() {
        byte[] data = Utils.convertToHex("00112233445566778899aabbccddeeff");
        aes.initEncrypt(Utils.convertToHex("000102030405060708090a0b0c0d0e0f"));
        byte[] res = aes.process(Arrays.copyOf(data, data.length));
        res = Arrays.copyOf(res, res.length);
        aes.finish();
        
        aes.initDecrypt(Utils.convertToHex("000102030405060708090a0b0c0d0e0f"));
        assertArrayEquals(data, aes.process(res));
    }

    @Test(expected = IllegalArgumentException.class)
    public void notAllowingKeyOfWrongSize() {
        aes.initEncrypt(new byte[] { 1 });
    }

    @Test(expected = IllegalArgumentException.class)
    public void notAllowingBlockOfWrongSize() {
        aes.initEncrypt(Utils.convertToHex("000102030405060708090a0b0c0d0e0f"));
        aes.process(new byte[] { 1, 2 });
    }

    @Test(expected = IllegalStateException.class)
    public void notProcessBeforeInit() {
        aes.process(new byte[] { 1, 2 });
    }

    @Test(expected = IllegalStateException.class)
    public void notProcessAfterFinish() {
        aes.initEncrypt(Utils.convertToHex("000102030405060708090a0b0c0d0e0f"));
        aes.finish();
        aes.process(new byte[] { 1 });
    }
}
