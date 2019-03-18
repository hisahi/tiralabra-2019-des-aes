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
        des.finish();
    }

    @Test
    public void testEncrypt() {
        des.initEncrypt(new byte[] { 0x5B, 0x5A, 0x57, 0x67, 0x6A, 0x56, 0x67, 0x6E });
        byte[] res = des.process(new byte[] { 0x67, 0x5A, 0x69, 0x67, 0x5E, 0x5A, 0x6B, 0x5A });
        assertArrayEquals(new byte[] { (byte)0x97, 0x4A, (byte)0xFF, (byte)0xBF, (byte)0x86, 0x02, 0x2D, 0x1F }, res);
    }

    @Test
    public void testEncrypt2() {
        des.initEncrypt(new byte[] { (byte)0x85, 0x3F, 0x31, 0x35, 0x1E, 0x51, (byte)0xCD, (byte)0x9C });
        byte[] res = des.process(new byte[] { 10, 15, 44, -79, -66, -2, 29, 0 });
        assertArrayEquals(new byte[] { (byte)0xC3, 0x66, 0x1F, 0x19, 0x25, (byte)0xC8, (byte)0xE8, (byte)0xC2 }, res);
    }

    @Test
    public void testDecrypt() {
        des.initDecrypt(new byte[] { 0x5B, 0x5A, 0x57, 0x67, 0x6A, 0x56, 0x67, 0x6E });
        byte[] res = des.process(new byte[] { (byte)0x97, 0x4A, (byte)0xFF, (byte)0xBF, (byte)0x86, 0x02, 0x2D, 0x1F });
        assertArrayEquals(new byte[] { 0x67, 0x5A, 0x69, 0x67, 0x5E, 0x5A, 0x6B, 0x5A }, res);
    }

    @Test
    public void testEncryptAndDecrypt() {
        byte[] data = new byte[] { 0x67, 0x5A, 0x69, 0x67, 0x5E, 0x5A, 0x6B, 0x5A };
        des.initEncrypt(new byte[] { 0x5B, 0x5A, 0x57, 0x67, 0x6A, 0x56, 0x67, 0x6E });
        byte[] res = des.process(data);
        res = Arrays.copyOf(res, res.length);
        des.finish();
        
        des.initDecrypt(new byte[] { 0x5B, 0x5A, 0x57, 0x67, 0x6A, 0x56, 0x67, 0x6E });
        assertArrayEquals(data, des.process(data));
    }
}
