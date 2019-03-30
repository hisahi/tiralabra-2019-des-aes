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

    /**
     * Test case for 128-bit AES encryption. The result has been tested
     * against an implementation known to work correctly.
     */
    @Test
    public void testEncrypt128() {
        aes.initEncrypt(Utils.convertHexToBytes("000102030405060708090a0b0c0d0e0f"));
        byte[] res = aes.process(Utils.convertHexToBytes("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertHexToBytes("69c4e0d86a7b0430d8cdb78070b4c55a"), res);
    }
    
    /**
     * Test case for 192-bit AES encryption. The result has been tested
     * against an implementation known to work correctly.
     */
    @Test
    public void testEncrypt192() {
        aes.initEncrypt(Utils.convertHexToBytes("aa9dca3ba4de72155c652ae17cfa6926cfd12addbb2b212c"));
        byte[] res = aes.process(Utils.convertHexToBytes("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertHexToBytes("a174c3f09dcac31edc78ed7c5b816a75"), res);
    }

    /**
     * Test case for 256-bit AES encryption. The result has been tested
     * against an implementation known to work correctly.
     */
    @Test
    public void testEncrypt256() {
        aes.initEncrypt(Utils.convertHexToBytes("b6d40ab01a80415ae8ee56bc7998ed12ac017d3fd5433373c578fbb117906b18"));
        byte[] res = aes.process(Utils.convertHexToBytes("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertHexToBytes("305ac3d618fcf837b25772f5720b4aad"), res);
    }

    /**
     * Test case for 128-bit AES decryption. The result has been tested
     * against an implementation known to work correctly.
     */
    @Test
    public void testDecrypt128() {
        aes.initDecrypt(Utils.convertHexToBytes("000102030405060708090a0b0c0d0e0f"));
        byte[] res = aes.process(Utils.convertHexToBytes("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertHexToBytes("762a5ab50929189cefdb99434790aad8"), res);
    }

    /**
     * Test case for 192-bit AES decryption. The result has been tested
     * against an implementation known to work correctly.
     */
    @Test
    public void testDecrypt192() {
        aes.initDecrypt(Utils.convertHexToBytes("aa9dca3ba4de72155c652ae17cfa6926cfd12addbb2b212c"));
        byte[] res = aes.process(Utils.convertHexToBytes("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertHexToBytes("1521e2e918e8e9928680fc78a2face1b"), res);
    }

    /**
     * Test case for 256-bit AES decryption. The result has been tested
     * against an implementation known to work correctly.
     */
    @Test
    public void testDecrypt256() {
        aes.initDecrypt(Utils.convertHexToBytes("b6d40ab01a80415ae8ee56bc7998ed12ac017d3fd5433373c578fbb117906b18"));
        byte[] res = aes.process(Utils.convertHexToBytes("00112233445566778899aabbccddeeff"));
        assertArrayEquals(Utils.convertHexToBytes("5b0a8fdb94985103947629f1caa42518"), res);
    }

    /**
     * Testing that encryption and decryption returns the original data.
     */
    @Test
    public void testEncryptAndDecrypt128() {
        byte[] data = Utils.convertHexToBytes("00112233445566778899aabbccddeeff");
        aes.initEncrypt(Utils.convertHexToBytes("000102030405060708090a0b0c0d0e0f"));
        byte[] res = aes.process(Arrays.copyOf(data, data.length));
        res = Arrays.copyOf(res, res.length);
        aes.finish();
        
        aes.initDecrypt(Utils.convertHexToBytes("000102030405060708090a0b0c0d0e0f"));
        assertArrayEquals(data, aes.process(res));
    }

    /**
     * The cipher should not accept keys of wrong size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void notAllowingKeyOfWrongSize() {
        aes.initEncrypt(new byte[] { 1 });
    }

    /**
     * The cipher should not accept blocks of wrong size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void notAllowingBlockOfWrongSize() {
        aes.initEncrypt(Utils.convertHexToBytes("000102030405060708090a0b0c0d0e0f"));
        aes.process(new byte[] { 1, 2 });
    }

    /**
     * process() should raise an exception when called before the cipher
     * is initialized.
     */
    @Test(expected = IllegalStateException.class)
    public void notProcessBeforeInit() {
        aes.process(new byte[] { 1, 2 });
    }

    /**
     * process() should raise an exception when called between a call
     * to finish() and a new initialization.
     */
    @Test(expected = IllegalStateException.class)
    public void notProcessAfterFinish() {
        aes.initEncrypt(Utils.convertHexToBytes("000102030405060708090a0b0c0d0e0f"));
        aes.finish();
        aes.process(new byte[] { 1 });
    }
}
