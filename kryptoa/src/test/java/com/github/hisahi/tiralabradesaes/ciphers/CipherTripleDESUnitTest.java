/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.hisahi.tiralabradesaes.ciphers;

import java.util.Arrays;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author hopea
 */
public class CipherTripleDESUnitTest {
    
    private static final byte[] tdeskey = new byte[] { (byte)0x85, 0x3F, 0x31, 0x35, 0x1E, 0x51, (byte)0xCD, (byte)0x9C, 0x52, 0x22, (byte)0xC2, (byte)0x8E, 0x40, (byte)0x8B, (byte)0xF2, (byte)0xA3, (byte)0x85, 0x3F, 0x31, 0x35, 0x1E, 0x51, (byte)0xCD, (byte)0x9C };
    private CipherTripleDES tdes;
    
    public CipherTripleDESUnitTest() {
    }
    
    @Before
    public void setUp() {
        tdes = new CipherTripleDES();
    }
    
    @After
    public void tearDown() {
        tdes.finish();
    }

    @Test
    public void testEncrypt() {
        tdes.initEncrypt(tdeskey);
        byte[] res = tdes.process(new byte[] { 0x67, 0x5A, 0x69, 0x67, 0x5E, 0x5A, 0x6B, 0x5A });
        assertArrayEquals(new byte[] { (byte)0xC3, 0x66, 0x1F, 0x19, 0x25, (byte)0xC8, (byte)0xE8, (byte)0xC2 }, res);
    }

    @Test
    public void testDecrypt() {
        tdes.initDecrypt(tdeskey);
        byte[] res = tdes.process(new byte[] { (byte)0xC3, 0x66, 0x1F, 0x19, 0x25, (byte)0xC8, (byte)0xE8, (byte)0xC2 });
        assertArrayEquals(new byte[] { 0x67, 0x5A, 0x69, 0x67, 0x5E, 0x5A, 0x6B, 0x5A }, res);
    }

    @Test
    public void testEncryptAndDecrypt() {
        byte[] data = new byte[] { 0x67, 0x5A, 0x69, 0x67, 0x5E, 0x5A, 0x6B, 0x5A };
        tdes.initEncrypt(tdeskey);
        byte[] res = tdes.process(data);
        res = Arrays.copyOf(res, res.length);
        tdes.finish();
        
        tdes.initDecrypt(tdeskey);
        assertArrayEquals(data, tdes.process(data));
    }
}
