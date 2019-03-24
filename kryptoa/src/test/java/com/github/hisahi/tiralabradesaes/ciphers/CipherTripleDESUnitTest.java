package com.github.hisahi.tiralabradesaes.ciphers;

import com.github.hisahi.tiralabradesaes.Utils;
import java.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CipherTripleDESUnitTest {
    
    private static final byte[] tdeskey = Utils.convertToHex("853F31351E51CD9C5222C28E408BF2A3853F31351E51CD9C");
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

    @Test
    public void testEncrypt() {
        tdes.initEncrypt(tdeskey);
        byte[] res = tdes.process(Utils.convertToHex("675A69675E5A6B5A"));
        assertArrayEquals(Utils.convertToHex("C3661F1925C8E8C2"), res);
    }

    @Test
    public void testDecrypt() {
        tdes.initDecrypt(tdeskey);
        byte[] res = tdes.process(Utils.convertToHex("C3661F1925C8E8C2"));
        assertArrayEquals(Utils.convertToHex("675A69675E5A6B5A"), res);
    }

    @Test
    public void testEncryptAndDecrypt() {
        byte[] data = Utils.convertToHex("675A69675E5A6B5A");
        tdes.initEncrypt(tdeskey);
        byte[] res = tdes.process(Arrays.copyOf(data, data.length));
        res = Arrays.copyOf(res, res.length);
        tdes.finish();
        
        tdes.initDecrypt(tdeskey);
        assertArrayEquals(data, tdes.process(res));
    }

    @Test(expected = IllegalArgumentException.class)
    public void notAllowingKeyOfWrongSize() {
        tdes.initEncrypt(Utils.convertToHex("01"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void notAllowingBlockOfWrongSize() {
        tdes.initEncrypt(Utils.convertToHex("5B5A57676A56676E5B5A57676A56676E5B5A57676A56676E"));
        tdes.process(Utils.convertToHex("01"));
    }

    @Test(expected = IllegalStateException.class)
    public void notProcessBeforeInit() {
        tdes.process(Utils.convertToHex("01"));
    }

    @Test(expected = IllegalStateException.class)
    public void notProcessAfterFinish() {
        tdes.initEncrypt(Utils.convertToHex("5B5A57676A56676E5B5A57676A56676E5B5A57676A56676E"));
        tdes.finish();
        tdes.process(Utils.convertToHex("01"));
    }
}
