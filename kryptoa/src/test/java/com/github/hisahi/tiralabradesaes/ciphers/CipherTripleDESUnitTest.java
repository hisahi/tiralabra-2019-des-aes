package com.github.hisahi.tiralabradesaes.ciphers;

import com.github.hisahi.tiralabradesaes.Utils;
import java.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CipherTripleDESUnitTest {
    
    private static final byte[] tdeskey = Utils.convertHexToBytes("853F31351E51CD9C5222C28E408BF2A3853F31351E51CD9C");
    private CipherTripleDES tdes;
    
    public CipherTripleDESUnitTest() {
    }
    
    @Before
    public void setUp() {
        tdes = new CipherTripleDES();
    }
    
    @After
    public void tearDown() {
        try {
            tdes.finish();
        } catch (IllegalStateException ex) {}
    }

    /**
     * Test case for 3DES encryption. The result has been tested against an 
     * implementation known to work correctly.
     */
    @Test
    public void testEncrypt() {
        tdes.initEncrypt(tdeskey);
        byte[] res = tdes.process(Utils.convertHexToBytes("675A69675E5A6B5A"));
        assertArrayEquals(Utils.convertHexToBytes("C3661F1925C8E8C2"), res);
    }

    /**
     * Test case for 3DES decryption. The result has been tested against an 
     * implementation known to work correctly.
     */
    @Test
    public void testDecrypt() {
        tdes.initDecrypt(tdeskey);
        byte[] res = tdes.process(Utils.convertHexToBytes("C3661F1925C8E8C2"));
        assertArrayEquals(Utils.convertHexToBytes("675A69675E5A6B5A"), res);
    }

    /**
     * Testing that encryption and decryption returns the original data.
     */
    @Test
    public void testEncryptAndDecrypt() {
        byte[] data = Utils.convertHexToBytes("675A69675E5A6B5A");
        tdes.initEncrypt(tdeskey);
        byte[] res = tdes.process(Arrays.copyOf(data, data.length));
        res = Arrays.copyOf(res, res.length);
        tdes.finish();
        
        tdes.initDecrypt(tdeskey);
        assertArrayEquals(data, tdes.process(res));
    }

    /**
     * The cipher should not accept keys of wrong size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void notAllowingKeyOfWrongSize() {
        tdes.initEncrypt(Utils.convertHexToBytes("01"));
    }

    /**
     * The cipher should not accept blocks of wrong size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void notAllowingBlockOfWrongSize() {
        tdes.initEncrypt(Utils.convertHexToBytes("5B5A57676A56676E5B5A57676A56676E5B5A57676A56676E"));
        tdes.process(Utils.convertHexToBytes("01"));
    }

    /**
     * process() should raise an exception when called before the cipher
     * is initialized.
     */
    @Test(expected = IllegalStateException.class)
    public void notProcessBeforeInit() {
        tdes.process(Utils.convertHexToBytes("01"));
    }

    /**
     * process() should raise an exception when called between a call
     * to finish() and a new initialization.
     */
    @Test(expected = IllegalStateException.class)
    public void notProcessAfterFinish() {
        tdes.initEncrypt(Utils.convertHexToBytes("5B5A57676A56676E5B5A57676A56676E5B5A57676A56676E"));
        tdes.finish();
        tdes.process(Utils.convertHexToBytes("01"));
    }
}
