/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.hisahi.tiralabradesaes;

import static org.junit.Assert.*;
import org.junit.Test;

/**
 *
 * @author hopea
 */
public class UtilsTest {
    @Test
    public void testPrepareDESKey() {
        assertArrayEquals(new byte[] {74, (byte)185, (byte)158, 47, 7, (byte)162, (byte)188, (byte)194}, 
                          Utils.prepareDESKey(new byte[] {0x4b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61}));
    }
    
    @Test
    public void testPrepare3DESKey() {
        assertArrayEquals(new byte[] {74, (byte)185, (byte)158, 47, 7, (byte)162, (byte)188, (byte)194,
                                      26, (byte)185, (byte)158, 47, 7, (byte)162, (byte)188, (byte)194,
                                      42, (byte)185, (byte)158, 47, 7, (byte)162, (byte)188, (byte)194}, 
                          Utils.prepare3DESKey(new byte[] {0x4b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61,
                                                           0x1b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61,
                                                           0x2b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61}));
    }
    
    @Test
    public void testPrepare3DESKeyFrom14Bytes() {
        assertArrayEquals(new byte[] {74, (byte)185, (byte)158, 47, 7, (byte)162, (byte)188, (byte)194,
                                      42, (byte)185, (byte)158, 47, 7, (byte)162, (byte)188, (byte)194,
                                      74, (byte)185, (byte)158, 47, 7, (byte)162, (byte)188, (byte)194}, 
               Utils.prepare3DESKeyFrom14Bytes(new byte[] {0x4b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61,
                                                           0x2b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61}));
    }
    
    @Test
    public void testPrepare3DESKeyFrom16Bytes() {
        assertArrayEquals(new byte[] {(byte)0x85, 0x3F, 0x31, 0x35, 0x1E, 0x51, (byte)0xCD, (byte)0x9C,
                                      0x52, 0x22, (byte)0xC2, (byte)0x8E, 0x40, (byte)0x8B, (byte)0xF2, (byte)0xA3,
                                      (byte)0x85, 0x3F, 0x31, 0x35, 0x1E, 0x51, (byte)0xCD, (byte)0x9C}, 
           Utils.prepare3DESKeyFrom16Bytes(new byte[] {(byte)0x85, 0x3F, 0x31, 0x35, 0x1E, 0x51, (byte)0xCD, (byte)0x9C,
                                                       0x52, 0x22, (byte)0xC2, (byte)0x8E, 0x40, (byte)0x8B, (byte)0xF2, (byte)0xA3}));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testPrepareDESKeyInvalidSize() {
        Utils.prepareDESKey(new byte[] {0});
    }
    
    
    @Test(expected = IllegalArgumentException.class)
    public void testPrepare3DESKeyInvalidSize() {
        Utils.prepare3DESKey(new byte[] {0});
    }
    
    
    @Test(expected = IllegalArgumentException.class)
    public void testPrepare3DESKeyFrom14BytesInvalidSize() {
        Utils.prepare3DESKeyFrom14Bytes(new byte[] {0});
    }
    
    
    @Test(expected = IllegalArgumentException.class)
    public void testPrepare3DESKeyFrom16BytesInvalidSize() {
        Utils.prepare3DESKeyFrom16Bytes(new byte[] {0});
    }
    
    @Test
    public void testConvertToHex() {
        assertArrayEquals(new byte[] {0, 17, 34}, Utils.convertToHex("001122"));
        assertArrayEquals(new byte[] {-1, -128}, Utils.convertToHex("ff 80"));
        assertArrayEquals(new byte[] {}, Utils.convertToHex(""));
        assertArrayEquals(null, Utils.convertToHex("f"));
        assertArrayEquals(null, Utils.convertToHex("ggg"));
    }
}
