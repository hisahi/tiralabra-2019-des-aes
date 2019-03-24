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

    @Test
    public void testEncrypt() {
        des.initEncrypt(Utils.convertToHex("5B5A57676A56676E"));
        byte[] res = des.process(Utils.convertToHex("675A69675E5A6B5A"));
        assertArrayEquals(Utils.convertToHex("974AFFBF86022D1F"), res);
    }

    @Test
    public void testEncrypt2() {
        des.initEncrypt(Utils.convertToHex("853F31351E51CD9C"));
        byte[] res = des.process(Utils.convertToHex("0A0F2CB1BEFE1D00"));
        assertArrayEquals(Utils.convertToHex("C3661F1925C8E8C2"), res);
    }

    @Test
    public void testDecrypt() {
        des.initDecrypt(Utils.convertToHex("5B5A57676A56676E"));
        byte[] res = des.process(Utils.convertToHex("974AFFBF86022D1F"));
        assertArrayEquals(Utils.convertToHex("675A69675E5A6B5A"), res);
    }

    @Test
    public void testEncryptAndDecrypt() {
        byte[] data = Utils.convertToHex("675A69675E5A6B5A");
        des.initEncrypt(Utils.convertToHex("5B5A57676A56676E"));
        byte[] res = des.process(Arrays.copyOf(data, data.length));
        res = Arrays.copyOf(res, res.length);
        des.finish();
        
        des.initDecrypt(Utils.convertToHex("5B5A57676A56676E"));
        assertArrayEquals(data, des.process(res));
    }

    @Test(expected = IllegalArgumentException.class)
    public void notAllowingKeyOfWrongSize() {
        des.initEncrypt(Utils.convertToHex("01"));
    }

    @Test(expected = IllegalArgumentException.class)
    public void notAllowingBlockOfWrongSize() {
        des.initEncrypt(Utils.convertToHex("5B5A57676A56676E"));
        des.process(Utils.convertToHex("01"));
    }

    @Test(expected = IllegalStateException.class)
    public void notProcessBeforeInit() {
        des.process(Utils.convertToHex("01"));
    }

    @Test(expected = IllegalStateException.class)
    public void notProcessAfterFinish() {
        des.initEncrypt(Utils.convertToHex("5B5A57676A56676E"));
        des.finish();
        des.process(Utils.convertToHex("01"));
    }
}

