
package com.github.hisahi.tiralabradesaes; 

import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

/**
 * Various utility functions to be used by other code. Cannot be instantiated.
 */
public final class Utils {
    private static final String HEX_DIGITS = "0123456789abcdef";
    private static final Random rng = new Random();
    
    /**
     * Converts a 7-byte 56-bit DES key to the full 8-byte 64-bit DES key.
     * These keys both contain 56 bits of information and therefore have 56
     * bits of security; the remaining 8 bits are parity bits.
     * 
     * @param rawKey The 7-byte 56-bit DES key.
     * @return The given key as an 8-byte 64-bit DES key with 56 bits of 
     *         security.
     */
    public static byte[] prepareDESKey(byte[] rawKey) {
        if (rawKey.length != 7) {
            throw new IllegalArgumentException("must give 7-byte 56-bit key to prepare");
        }
        byte[] prepKey = new byte[8];
        prepKey[0] = (byte) (rawKey[0] & 0xFE);
        prepKey[1] = (byte) (((rawKey[0] & 0x01) << 7) | ((rawKey[1] & 0xFC) >> 1));
        prepKey[2] = (byte) (((rawKey[1] & 0x03) << 6) | ((rawKey[2] & 0xF8) >> 2));
        prepKey[3] = (byte) (((rawKey[2] & 0x07) << 5) | ((rawKey[3] & 0xF0) >> 3));
        prepKey[4] = (byte) (((rawKey[3] & 0x0F) << 4) | ((rawKey[4] & 0xE0) >> 4));
        prepKey[5] = (byte) (((rawKey[4] & 0x1F) << 3) | ((rawKey[5] & 0xC0) >> 5));
        prepKey[6] = (byte) (((rawKey[5] & 0x3F) << 2) | ((rawKey[6] & 0x80) >> 6));
        prepKey[7] = (byte) (((rawKey[6] & 0x7F) << 1));
        // now 0x00 < prepKey[0..8] < 0x80
        // now add parity
        for (int i = 0; i < 8; ++i) {
            // parity goes to lowest bit
            prepKey[i] ^= computeOddParityMask(prepKey[i]);
        }
        return prepKey;
    }
    
    /**
     * Converts a 14-byte 112-bit 3DES key to the full 24-byte 192-bit 3DES key.
     * The resulting key will have 112 bits of security, with the third key
     * being equivalent to the first key.
     * 
     * @param rawKey The 14-byte 112-bit 3DES key.
     * @return The given key as an 24-byte 192-bit 3DES key with 112 bits of 
     *         security.
     */
    public static byte[] prepare3DESKeyFrom14Bytes(byte[] rawKey) {
        if (rawKey.length != 14) {
            throw new IllegalArgumentException("must give 14-byte 112-bit key to prepare");
        }
        byte[] midKey = new byte[21];
        
        // K1 <- K1, K2 <- K2, K3 <- K1
        System.arraycopy(rawKey, 0, midKey, 0, 14);
        System.arraycopy(rawKey, 0, midKey, 14, 7);
        
        byte[] resKey = prepare3DESKey(midKey);
        destroyArray(midKey);
        return resKey;
    }
    
    /**
     * Converts a 21-byte 168-bit 3DES key to the full 24-byte 192-bit 3DES key.
     * These keys both contain 168 bits of information and therefore have 168
     * bits of security; the remaining 24 bits are parity bits.
     * 
     * @param rawKey The 21-byte 168-bit 3DES key.
     * @return The given key as an 24-byte 192-bit 3DES key with 168 bits of 
     *         security.
     */
    public static byte[] prepare3DESKey(byte[] rawKey) {
        if (rawKey.length != 21) {
            throw new IllegalArgumentException("must give 21-byte 168-bit key to prepare");
        }
        byte[] prepKeys = new byte[24];
        
        byte[] subkey1 = Arrays.copyOfRange(rawKey,  0,  7);
        byte[] subkey2 = Arrays.copyOfRange(rawKey,  7, 14);
        byte[] subkey3 = Arrays.copyOfRange(rawKey, 14, 21);
        
        byte[] prepKey1 = prepareDESKey(subkey1);
        byte[] prepKey2 = prepareDESKey(subkey2);
        byte[] prepKey3 = prepareDESKey(subkey3);
        
        for (int i = 0; i < 8; ++i) {
            prepKeys[i     ] = prepKey1[i];
            prepKeys[i +  8] = prepKey2[i];
            prepKeys[i + 16] = prepKey3[i];
            prepKey1[i] = prepKey2[i] = prepKey3[i] = 0;
        }
        for (int i = 0; i < 7; ++i) {
            subkey1[i] = subkey2[i] = subkey3[i] = 0;
        }
        return prepKeys;
    }
    
    /**
     * Converts a 16-byte 128-bit 3DES key to the full 24-byte 192-bit 3DES key.
     * The resulting key will have 112 bits of security, with the third key
     * being equivalent to the first key.
     * 
     * @param rawKey The 16-byte 128-bit 3DES key.
     * @return The given key as an 24-byte 192-bit 3DES key with 112 bits of 
     *         security.
     */
    public static byte[] prepare3DESKeyFrom16Bytes(byte[] rawKey) {
        if (rawKey.length != 16) {
            throw new IllegalArgumentException("must give 16-byte 128-bit key to prepare");
        }
        byte[] resKey = new byte[24];
        
        // K1 <- K1, K2 <- K2, K3 <- K1
        System.arraycopy(rawKey, 0, resKey, 0, 16);
        System.arraycopy(rawKey, 0, resKey, 16, 8);
        
        return resKey;
    }
    
    private static byte computeOddParityMask(byte x) {
        byte b = 1;
        for (int i = 0; i < 7; ++i) {
            b ^= 1 & (x >>> (7 - i));
        }
        return b;
    }
    
    /**
     * Wipes the contents of the given byte[] array.
     * 
     * @param arr The array to wipe.
     * @return Meaningless number.
     */
    public static int destroyArray(byte[] arr) {
        int j = 0;
        for (int i = 0; i < arr.length; ++i) {
            arr[i] = (byte) ((0x55 ^ (0xFF - ((i & 255) * 149))) ^ rng.nextInt());
            j = (j + i + arr[i]) % 257;
        }
        return j;
    }
    
    /**
     * Wipes the contents of the given int[] array.
     * 
     * @param arr The array to wipe.
     * @return Meaningless number.
     */
    public static int destroyArray(int[] arr) {
        int j = 0;
        for (int i = 0; i < arr.length; ++i) {
            arr[i] = ((0x55AA55AA ^ (i * -732137189)) ^ rng.nextInt());
            j = (j + i + arr[i]);
        }
        return j;
    }

    /**
     * Converts the given hex string to a byte array. The string is expected
     * to contain an even number of hex digits, possibly spaced apart. If the
     * format is not recognized, the function will return null.
     * 
     * An empty string will not return null but an empty byte array, that is
     * a byte[] with length 0.
     * 
     * @param str The hex string to convert.
     * @return The converted byte array or null if the string is invalid.
     */
    public static byte[] convertToHex(String str) {
        // remove spaces
        str = str.replace(" ", "");
        // odd length -> invalid
        if (str.length() % 2 != 0) return null;
        
        byte[] res = new byte[str.length() / 2];
        int j = 0;
        for (int i = 0; i < str.length(); i += 2) {
            int sixteens = HEX_DIGITS.indexOf(str.toLowerCase().charAt(i));
            int ones = HEX_DIGITS.indexOf(str.toLowerCase().charAt(i + 1));
            
            if (ones < 0 || sixteens < 0) {
                // invalid hex digit
                return null;
            }
            
            res[j++] = (byte) (sixteens * 16 + ones);
        }
        
        return res;
    }

    /**
     * Dumps the given byte array with the given length into stdout as
     * hex. This function is primarily for debugging purposes.
     * 
     * @param block The block to dump into stdout.
     * @param length The length of the block to dump.
     */
    public static void dumpBlock(byte[] block, int length) {
        for (int i = 0; i < length; ++i) {
            System.out.print(String.format("%02x", block[i] & 0xFF));
        }
        System.out.println("");
    }
    
    private Utils() {}
}
