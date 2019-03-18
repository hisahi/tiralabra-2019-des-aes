
package com.github.hisahi.tiralabradesaes; 

import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Utils {
    private static final String HEX_DIGITS = "0123456789abcdef";
    private static Random rng = new Random();
    
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
            prepKey[i] <<= 1;
            // parity goes to lowest bit
            prepKey[i] ^= computeOddParityMask(prepKey[i]);
        }
        return prepKey;
    }
    
    public static byte[] prepare3DESKey(byte[] rawKey) {
        if (rawKey.length !=21) {
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
    
    private static byte computeOddParityMask(byte x) {
        byte b = 1;
        for (int i = 0; i < 7; ++i) {
            b ^= 1 & (x << (7 - i));
        }
        return b;
    }
    
    public static int destroyArray(byte[] arr) {
        int j = 0;
        for (int i = 0; i < arr.length; ++i) {
            arr[i] = (byte) ((0x55 ^ (0xFF - ((i & 255) * 149))) ^ rng.nextInt());
            j = (j + i + arr[i]) % 257;
        }
        return j;
    }

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

    public static void dumpBlock(byte[] block, int length) {
        for (int i = 0; i < length; ++i) {
            System.out.print(String.format("%02x", block[i] & 0xFF));
        }
        System.out.println("");
    }

    public static boolean confirmPrompt(String msg) {
        Scanner keyb = new Scanner(System.in);
        String token;
        String choice = "x";
        
        do {
            System.out.print(msg + " [Y/N]?");
            System.out.flush();
            
            token = keyb.next();
            if (!token.isEmpty()) {
                choice = token.toUpperCase().substring(0, 1);
            }
            
            System.out.println();
        } while (!"YN".contains(choice));
        
        return choice.equalsIgnoreCase("Y");
    }
    
    private Utils() {}
}
