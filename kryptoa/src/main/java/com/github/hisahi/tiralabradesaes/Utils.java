
package com.github.hisahi.tiralabradesaes; 

public class Utils {
    private static final byte b0x80 = (byte) 128;
    
    public static byte[] prepareDESKey(byte[] rawKey) {
        if (rawKey.length != 7) {
            throw new IllegalArgumentException("must give 7-byte 56-bit key to prepare");
        }
        byte[] prepKey = new byte[8];
        prepKey[0] = (byte) ((rawKey[0] & 0xFE) >> 1);
        prepKey[1] = (byte) (((rawKey[0] & 0x01) << 7) | ((rawKey[1] & 0xFC) >> 2));
        prepKey[2] = (byte) (((rawKey[1] & 0x03) << 6) | ((rawKey[2] & 0xF8) >> 3));
        prepKey[3] = (byte) (((rawKey[2] & 0x07) << 5) | ((rawKey[3] & 0xF0) >> 4));
        prepKey[4] = (byte) (((rawKey[3] & 0x0F) << 4) | ((rawKey[4] & 0xE0) >> 5));
        prepKey[5] = (byte) (((rawKey[4] & 0x1F) << 3) | ((rawKey[5] & 0xC0) >> 6));
        prepKey[6] = (byte) (((rawKey[5] & 0x3F) << 2) | ((rawKey[6] & 0x80) >> 7));
        prepKey[7] = (byte) (((rawKey[6] & 0x7F) << 1));
        // now 0x00 < prepKey[0..8] < 0x80
        // now add parity
        for (int i = 0; i < 8; ++i) {
            prepKey[i] ^= computeOddParityMask(prepKey[i]);
        }
        return prepKey;
    }
    
    private static byte computeOddParityMask(byte x) {
        byte b = b0x80;
        for (int i = 0; i < 7; ++i) {
            b ^= b0x80 & (x << (7 - i));
        }
        return b;
    }
    
    public static int destroyArray(byte[] arr) {
        int j = 0;
        for (int i = 0; i < arr.length; ++i) {
            arr[i] = (byte) (0x55 ^ (0xFF - ((i & 255) * 149)));
            j = (j + i + arr[i]) % 257;
        }
        return j;
    }

    public static void dumpBlock(byte[] block, int length) {
        for (int i = 0; i < length; ++i) {
            System.out.print(String.format("%02x", block[i] & 0xFF));
        }
        System.out.println("");
    }
    
    private Utils() {}
}
