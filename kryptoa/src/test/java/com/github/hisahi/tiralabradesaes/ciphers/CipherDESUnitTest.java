package com.github.hisahi.tiralabradesaes.ciphers;

import com.github.hisahi.tiralabradesaes.Utils;
import java.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CipherDESUnitTest {
    
    private CipherDES des;
    
    public CipherDESUnitTest() {
    }
    
    @Before
    public void setUp() {
        des = new CipherDES();
    }
    
    @After
    public void tearDown() {
        try {
            des.finish();
        } catch (IllegalStateException ex) {}
    }

    /**
     * Test case for DES encryption. The result has been tested against an 
     * implementation known to work correctly.
     */
    @Test
    public void testEncrypt() {
        des.initEncrypt(Utils.convertHexToBytes("5B5A57676A56676E"));
        byte[] res = des.process(Utils.convertHexToBytes("675A69675E5A6B5A"));
        assertArrayEquals(Utils.convertHexToBytes("974AFFBF86022D1F"), res);
    }

    /**
     * Test case for DES encryption. The result has been tested against an 
     * implementation known to work correctly.
     */
    @Test
    public void testEncrypt2() {
        des.initEncrypt(Utils.convertHexToBytes("853F31351E51CD9C"));
        byte[] res = des.process(Utils.convertHexToBytes("0A0F2CB1BEFE1D00"));
        assertArrayEquals(Utils.convertHexToBytes("C3661F1925C8E8C2"), res);
    }

    /**
     * Test case for DES decryption. The result has been tested against an 
     * implementation known to work correctly.
     */
    @Test
    public void testDecrypt() {
        des.initDecrypt(Utils.convertHexToBytes("5B5A57676A56676E"));
        byte[] res = des.process(Utils.convertHexToBytes("974AFFBF86022D1F"));
        assertArrayEquals(Utils.convertHexToBytes("675A69675E5A6B5A"), res);
    }

    /**
     * Testing that encryption and decryption returns the original data.
     */
    @Test
    public void testEncryptAndDecrypt() {
        byte[] data = Utils.convertHexToBytes("675A69675E5A6B5A");
        des.initEncrypt(Utils.convertHexToBytes("5B5A57676A56676E"));
        byte[] res = des.process(Arrays.copyOf(data, data.length));
        res = Arrays.copyOf(res, res.length);
        des.finish();
        
        des.initDecrypt(Utils.convertHexToBytes("5B5A57676A56676E"));
        assertArrayEquals(data, des.process(res));
    }

    /**
     * The cipher should not accept keys of wrong size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void notAllowingKeyOfWrongSize() {
        des.initEncrypt(Utils.convertHexToBytes("01"));
    }

    /**
     * The cipher should not accept blocks of wrong size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void notAllowingBlockOfWrongSize() {
        des.initEncrypt(Utils.convertHexToBytes("5B5A57676A56676E"));
        des.process(Utils.convertHexToBytes("01"));
    }

    /**
     * process() should raise an exception when called before the cipher
     * is initialized.
     */
    @Test(expected = IllegalStateException.class)
    public void notProcessBeforeInit() {
        des.process(Utils.convertHexToBytes("01"));
    }

    /**
     * process() should raise an exception when called between a call
     * to finish() and a new initialization.
     */
    @Test(expected = IllegalStateException.class)
    public void notProcessAfterFinish() {
        des.initEncrypt(Utils.convertHexToBytes("5B5A57676A56676E"));
        des.finish();
        des.process(Utils.convertHexToBytes("01"));
    }
}

