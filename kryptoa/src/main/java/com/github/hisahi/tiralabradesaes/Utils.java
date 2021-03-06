
package com.github.hisahi.tiralabradesaes; 

import com.github.hisahi.tiralabradesaes.ciphers.CipherChaCha20;
import com.github.hisahi.tiralabradesaes.hash.HashSHA2_512;
import com.github.hisahi.tiralabradesaes.keyderiv.HMACFunction;
import com.github.hisahi.tiralabradesaes.keyderiv.IKeyDerivation;
import com.github.hisahi.tiralabradesaes.keyderiv.KeyDerivPBKDF2;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

/**
 * Various utility functions to be used by other code. Cannot be instantiated.
 */
public final class Utils {
    private static final String HEX_DIGITS = "0123456789abcdef";
            static final String B64_DIGITS = "ABCDEFGHIJKLMNOP"
                                           + "QRSTUVWXYZabcdef"
                                           + "ghijklmnopqrstuv"
                                           + "wxyz0123456789+/"
                                           + "="; // padding
    private static final MT19937 rng = new MT19937();
    private static CipherChaCha20 cha = null;
    
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
            throw new IllegalArgumentException("must give 7-byte 56-bit "
                                             + "key to prepare");
        }
        byte[] prepKey = new byte[8];
        prepKey[0] = (byte) (rawKey[0] & 0xFE);
        prepKey[1] = (byte) (((rawKey[0] & 0x01) << 7) 
                           | ((rawKey[1] & 0xFC) >> 1));
        prepKey[2] = (byte) (((rawKey[1] & 0x03) << 6) 
                           | ((rawKey[2] & 0xF8) >> 2));
        prepKey[3] = (byte) (((rawKey[2] & 0x07) << 5) 
                           | ((rawKey[3] & 0xF0) >> 3));
        prepKey[4] = (byte) (((rawKey[3] & 0x0F) << 4) 
                           | ((rawKey[4] & 0xE0) >> 4));
        prepKey[5] = (byte) (((rawKey[4] & 0x1F) << 3) 
                           | ((rawKey[5] & 0xC0) >> 5));
        prepKey[6] = (byte) (((rawKey[5] & 0x3F) << 2) 
                           | ((rawKey[6] & 0x80) >> 6));
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
            throw new IllegalArgumentException("must give 14-byte 112-bit "
                                             + "key to prepare");
        }
        byte[] midKey = new byte[21];
        
        // K1 <- K1, K2 <- K2, K3 <- K1
        arraycopy(rawKey, 0, midKey, 0, 14);
        arraycopy(rawKey, 0, midKey, 14, 7);
        
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
            throw new IllegalArgumentException("must give 21-byte 168-bit "
                                             + "key to prepare");
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
            throw new IllegalArgumentException("must give 16-byte 128-bit "
                                             + "key to prepare");
        }
        byte[] resKey = new byte[24];
        
        // K1 <- K1, K2 <- K2, K3 <- K1
        arraycopy(rawKey, 0, resKey, 0, 16);
        arraycopy(rawKey, 0, resKey, 16, 8);
        
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
            arr[i] = (byte) ((0x55 ^ (0xFF - ((i & 255) * 149))) 
                            ^ rng.nextInt());
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
    public static byte[] convertHexToBytes(String str) {
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
     * Converts the given Base64 string to a byte array. The string is expected
     * to contain only Base64 digits without any spacing. Digits 62 and 63
     * are + and / and the padding character is =.
     * 
     * An empty string will not return null but an empty byte array, that is
     * a byte[] with length 0.
     * 
     * @param str The Base64 string to convert.
     * @return The converted byte array or null if the string is invalid.
     */
    public static byte[] convertBase64ToBytes(String str) {
        byte[] res = new byte[str.length() * 3 / 4];
        int totalBytes = 0;
        
        if (str.length() % 4 != 0) {
            return null; // length must be divisible by 4
        }
        
        for (int i = 0; i < str.length(); i += 4) {
            int b1 = B64_DIGITS.indexOf(str.charAt(i));
            int b2 = B64_DIGITS.indexOf(str.charAt(i + 1));
            int b3 = B64_DIGITS.indexOf(str.charAt(i + 2));
            int b4 = B64_DIGITS.indexOf(str.charAt(i + 3));
            
            if (b1 < 0 || b2 < 0 || b3 < 0 || b4 < 0
                    || b1 == 64 || b2 == 64) {
                // invalid Base64
                return null;
            }
            
            res[totalBytes++] = (byte) ((b1 <<  2) | (b2 >>>  4));
            if (b3 < 64)
                res[totalBytes++] = (byte) ((b2 <<  4) | (b3 >>>  2));
            if (b4 < 64)
                res[totalBytes++] = (byte) ((b3 <<  6) | (b4       ));
        }
        
        return Arrays.copyOf(res, totalBytes);
    }
    
    /**
     * Converts the given byte array into a hex string consisting of
     * two hex digits for each byte, not separated with spaces or anything
     * else. The hex digits will be in lowercase.
     * 
     * @param b The byte array to convert.
     * @return The byte array as a hex string.
     */
    public static String convertBytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < b.length; ++i) {
            sb.append(String.format("%02x", b[i] & 0xFF));
        }
        
        return sb.toString();
    }

    /**
     * Fills the given byte array with random bytes NOT suitable for
     * cryptographic purposes.
     * 
     * Implementation detail: MT19937 is used to generate the numbers.
     * 
     * @param res The byte array to fill.
     */
    public static void generateWeakRandom(byte[] res) {
        rng.nextBytes(res);
    }

    /**
     * Fills the given byte array with random bytes generated using a 
     * cryptographically secure pseudo random number generator.
     * 
     * Implementation detail: ChaCha20, a stream cipher, is used to
     * generate the numbers; it is supplied a (weakly) random key and 
     * nonce, after which the cipher will supply strongly random
     * numbers.
     * 
     * @param res The byte array to fill.
     */
    public static void generateStrongRandom(byte[] res) {
        if (cha == null) {
            cha = new CipherChaCha20();
        }
        
        byte[] key = new byte[32];
        byte[] non = new byte[8];
        
        generateWeakRandom(key);
        generateWeakRandom(non);
        
        cha.init(key, non);
        arrayfill(res, (byte) 0);
        
        byte[] rnd = cha.process(res);
        cha.finish();
        
        arraycopy(rnd, 0, res, 0, res.length);
    }
    
    /**
     * Copies array contents from a source array into a destination
     * array. Undefined behavior if the two arrays are the same and the
     * source and destination regions overlap.
     * 
     * @param src The source array to copy from.
     * @param srcPos The position to start copying from.
     * @param dest The destination array to copy to.
     * @param destPos The position to start copying to.
     * @param length The number of elements to copy.
     */
    public static void arraycopy(byte[] src, int srcPos,
                                 byte[] dest, int destPos,
                                 int length) {
        // System.arraycopy(src, srcPos, dest, destPos, length);
        for (int i = 0; i < length; ++i) {
            dest[destPos + i] = src[srcPos + i];
        }
    }
    
    /**
     * Fills the entirety of the given array with the specific value.
     * 
     * @param a The array to fill.
     * @param val The value to fill with.
     */
    public static void arrayfill(byte[] a, byte val) {
        // Arrays.fill(a, val);
        for (int i = 0; i < a.length; ++i) {
            a[i] = val;
        }
    }
    
    /**
     * Fills the entirety of the given array with the specific value.
     * 
     * @param a The array to fill.
     * @param val The value to fill with.
     */
    public static void arrayfill(int[] a, int val) {
        // Arrays.fill(a, val);
        for (int i = 0; i < a.length; ++i) {
            a[i] = val;
        }
    }
    
    /**
     * Fills the entirety of the given array with the specific value.
     * 
     * @param a The array to fill.
     * @param val The value to fill with.
     */
    public static void arrayfill(long[] a, long val) {
        // Arrays.fill(a, val);
        for (int i = 0; i < a.length; ++i) {
            a[i] = val;
        }
    }
    
    /**
     * Dumps the given byte array with the given length into the standard
     * output as hex. This function is primarily for debugging purposes.
     * 
     * @param block The block to dump into standard output.
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
