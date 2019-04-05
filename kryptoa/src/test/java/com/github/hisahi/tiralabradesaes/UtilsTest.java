package com.github.hisahi.tiralabradesaes;

import static org.junit.Assert.*;
import org.junit.Test;

public class UtilsTest {
    /**
     * The 56-bit 7-byte DES key should be expanded correctly into a 64-bit
     * 8-byte DES key complete with padding.
     */
    @Test
    public void testPrepareDESKey() {
        assertArrayEquals(new byte[] {74, (byte)185, (byte)158, 47, 
                                      7, (byte)162, (byte)188, (byte)194}, 
                Utils.prepareDESKey(new byte[] {
                        0x4b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61}));
    }
    
    /**
     * The 168-bit 21-byte 3DES key should be expanded correctly into a 192-bit
     * 24-byte DES key complete with padding.
     */
    @Test
    public void testPrepare3DESKey() {
        assertArrayEquals(new byte[] {74, (byte)185, (byte)158, 47, 7, 
                                      (byte)162, (byte)188, (byte)194,
                                      26, (byte)185, (byte)158, 47, 7, 
                                      (byte)162, (byte)188, (byte)194,
                                      42, (byte)185, (byte)158, 47, 7, 
                                      (byte)162, (byte)188, (byte)194}, 
                Utils.prepare3DESKey(new byte[] {
                        0x4b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61,
                        0x1b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61,
                        0x2b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61}));
    }
    
    /**
     * The 112-bit 14-byte DES key should be expanded correctly into a 192-bit
     * 24-byte DES key complete with padding. The third of the three keys
     * should be equal to the first key.
     */
    @Test
    public void testPrepare3DESKeyFrom14Bytes() {
        assertArrayEquals(new byte[] {74, (byte)185, (byte)158, 47, 
                                      7, (byte)162, (byte)188, (byte)194,
                                      42, (byte)185, (byte)158, 47, 
                                      7, (byte)162, (byte)188, (byte)194,
                                      74, (byte)185, (byte)158, 47, 
                                      7, (byte)162, (byte)188, (byte)194}, 
               Utils.prepare3DESKeyFrom14Bytes(new byte[] {
                        0x4b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61,
                        0x2b, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x61}));
    }
    
    /**
     * The 128-bit 16-byte DES key should be expanded correctly into a 192-bit
     * 24-byte DES key. The third of the three keys should be equal to the
     * first key.
     */
    @Test
    public void testPrepare3DESKeyFrom16Bytes() {
        assertArrayEquals(new byte[] {(byte)0x85, 0x3F, 0x31, 0x35, 
                                      0x1E, 0x51, (byte)0xCD, (byte)0x9C,
                                      0x52, 0x22, (byte)0xC2, (byte)0x8E, 
                                      0x40, (byte)0x8B, (byte)0xF2, (byte)0xA3,
                                      (byte)0x85, 0x3F, 0x31, 0x35,
                                      0x1E, 0x51, (byte)0xCD, (byte)0x9C}, 
           Utils.prepare3DESKeyFrom16Bytes(new byte[] {
                        (byte)0x85, 0x3F, 0x31, 0x35, 
                        0x1E, 0x51, (byte)0xCD, (byte)0x9C,
                        0x52, 0x22, (byte)0xC2, (byte)0x8E, 
                        0x40, (byte)0x8B, (byte)0xF2, (byte)0xA3}));
    }
    
    /**
     * The DES key preparing function should reject keys with invalid size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testPrepareDESKeyInvalidSize() {
        Utils.prepareDESKey(new byte[] {0});
    }
    
    /**
     * The DES key preparing function should reject keys with invalid size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testPrepare3DESKeyInvalidSize() {
        Utils.prepare3DESKey(new byte[] {0});
    }
    
    /**
     * The DES key preparing function should reject keys with invalid size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testPrepare3DESKeyFrom14BytesInvalidSize() {
        Utils.prepare3DESKeyFrom14Bytes(new byte[] {0});
    }
    
    /**
     * The DES key preparing function should reject keys with invalid size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testPrepare3DESKeyFrom16BytesInvalidSize() {
        Utils.prepare3DESKeyFrom16Bytes(new byte[] {0});
    }
    
    /**
     * The function convertHexToBytes should correctly convert a series
     * of bytes represented in hex to a byte array and return null
     * in case of invalid input.
     */
    @Test
    public void testConvertHexToBytes() {
        assertArrayEquals(new byte[] {0, 17, 34}, 
                Utils.convertHexToBytes("001122"));
        assertArrayEquals(new byte[] {-1, -128}, 
                Utils.convertHexToBytes("ff 80"));
        assertArrayEquals(new byte[] {}, 
                Utils.convertHexToBytes(""));
        assertArrayEquals(null, 
                Utils.convertHexToBytes("f"));
        assertArrayEquals(null, 
                Utils.convertHexToBytes("ggg"));
    }
    
    /**
     * The function convertBase64ToBytes should correctly convert a series
     * of bytes represented in Base64 to a byte array and return null
     * in case of invalid input.
     */
    @Test
    public void testConvertBase64ToBytes() {
        assertArrayEquals(new byte[] {}, 
                Utils.convertBase64ToBytes(""));
        assertArrayEquals(new byte[] { 0x66 }, 
                Utils.convertBase64ToBytes("Zg=="));
        assertArrayEquals(new byte[] { 0x66, 0x6f }, 
                Utils.convertBase64ToBytes("Zm8="));
        assertArrayEquals(new byte[] { 0x66, 0x6f, 0x6f }, 
                Utils.convertBase64ToBytes("Zm9v"));
        assertArrayEquals(new byte[] { 0x66, 0x6f, 0x6f, 0x62 }, 
                Utils.convertBase64ToBytes("Zm9vYg=="));
        assertArrayEquals(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61 }, 
                Utils.convertBase64ToBytes("Zm9vYmE="));
        assertArrayEquals(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }, 
                Utils.convertBase64ToBytes("Zm9vYmFy"));
        assertEquals(null,  // invalid base64
                Utils.convertBase64ToBytes("Zm9"));
        assertEquals(null,  // invalid base64
                Utils.convertBase64ToBytes("Z(9="));
    }
    
    /**
     * The function convertBytesToHex should correctly convert any byte
     * array into a series of hex digits, two for each byte. The function
     * should give the hex digits in lowercase.
     */
    @Test
    public void testConvertBytesToHex() {
        assertEquals("", Utils.convertBytesToHex(new byte[] {}));
        assertEquals("0001020304", 
                Utils.convertBytesToHex(new byte[] { 0, 1, 2, 3, 4 }));
        assertEquals("0abcdef9", 
                Utils.convertBytesToHex(new byte[] { 10, -68, -34, -7 }));
        assertEquals("ff0055aa", 
                Utils.convertBytesToHex(new byte[] { -1, 0, 85, -86 }));
    }
    
    /**
     * Test that generating strong random bytes is possible. It's
     * impossible to actually test whether they are reliable.
     */
    @Test
    public void testStrongRandom() {
        byte[] b = new byte[16];
        Utils.generateStrongRandom(b);
    }
}
