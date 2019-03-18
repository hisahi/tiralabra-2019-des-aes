
package com.github.hisahi.tiralabradesaes.ui; 

import com.github.hisahi.tiralabradesaes.Utils;
import com.github.hisahi.tiralabradesaes.blockmodes.BlockModeCBC;
import com.github.hisahi.tiralabradesaes.blockmodes.BlockModeCTR;
import com.github.hisahi.tiralabradesaes.blockmodes.BlockModeECB;
import com.github.hisahi.tiralabradesaes.blockmodes.IBlockMode;
import com.github.hisahi.tiralabradesaes.ciphers.CipherAES;
import com.github.hisahi.tiralabradesaes.ciphers.CipherDES;
import com.github.hisahi.tiralabradesaes.ciphers.CipherTripleDES;
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;

/**
 * A class for representing the mode of operation of the program as given
 * by command-line parameters.
 */
class OperationMode {
    private final Direction direction;
    private final Cipher cipher;
    private final BlockMode blockmode;
    private final IOMode iomode;
    private final String key_str;
    private final String iv_str;
    private final String input;
    private final String output;
    
    public OperationMode(Direction dir, Cipher ciph, BlockMode bm, IOMode io, 
            String k, String nonce, String in, String out) {
        direction = dir;
        cipher = ciph;
        blockmode = bm;
        iomode = io;
        key_str = k;
        iv_str = nonce;
        input = in;
        output = out;
    }
    
    /**
     * Gets the chosen cipher (either DES, 3DES or AES).
     * 
     * @return The cipher chosen via parameters.
     */
    Cipher getCipherType() {
        return cipher;
    }
    
    /**
     * Gets the chosen block cipher mode of operation (either ECB, CBC or CTR).
     * 
     * @return The block cipher mode of operation chosen via parameters.
     */
    BlockMode getBlockModeType() {
        return blockmode;
    }
    
    /**
     * Gets the chosen I/O mode (either ASCII for raw stdin/stdout, HEX for
     * hex-encoded stdin/stdout or FILE for file I/O).
     * 
     * @return The I/O mode chosen via parameters.
     */
    IOMode getIOMode() {
        return iomode;
    }
    
    /**
     * Gets the direction of operation, either encryption or decryption.
     * 
     * @return The direction chosen via parameters.
     */
    Direction getDirection() {
        return direction;
    }
    
    /**
     * Gets the input string; the exact interpretation depends on the
     * chosen I/O mode.
     * 
     * For ASCII, this is either the string to encrypt/decrypt or empty
     * to read from stdin.
     * For HEX, this is the string to encrypt/decrypt given, with no
     * validation for whether it is correct hex.
     * For FILE, this is the input file name or path.
     * 
     * @return The input string given via parameters.
     */
    String getInputString() {
        return input;
    }
    
    /**
     * Gets the output string; the exact interpretation depends on the
     * chosen I/O mode.
     * 
     * For ASCII and HEX, this is empty.
     * For FILE, this is the output file name or path.
     * 
     * @return The output string given via parameters.
     */
    String getOutputString() {
        return output;
    }

    /**
     * Returns the chosen cipher as an instance of a class that conforms
     * to the IBlockCipher interface.
     * 
     * @return The cipher as a IBlockCipher.
     */
    IBlockCipher getCipher() {
        switch (cipher) {
            case DES:   return new CipherDES();
            case TDES:  return new CipherTripleDES();
            case AES:   return new CipherAES();
        }
        return null;
    }

    /**
     * Returns the chosen block mode of operation as an instance of a class
     * that conforms to the IBlockMode interface.
     * 
     * @return The block mode of operation as a IBlockMode.
     */
    IBlockMode getBlockMode(IBlockCipher ciph) {
        switch (blockmode) {
            case ECB:   return new BlockModeECB(ciph);
            case CBC:   return new BlockModeCBC(ciph);
            case CTR:   return new BlockModeCTR(ciph);
        }
        return null;
    }

    /**
     * Returns the key as a byte array, converted from the given hex string.
     * If the hex string given was invalid, this will return null.
     * 
     * @return Key given as a hex string parameter or null if invalid.
     */
    byte[] getKey() {
        return Utils.convertToHex(key_str);
    }

    /**
     * Returns the IV as a byte array, converted from the given hex string.
     * If the hex string given was invalid, this will return null.
     * For ECB mode, this will return an empty byte array, not null.
     * 
     * @return IV given as a hex string parameter or null if invalid.
     */
    byte[] getIV() {
        return Utils.convertToHex(iv_str);
    }
    
    /**
     * Represents the direction of operation.
     */
    enum Direction { 
        ENCRYPT, DECRYPT;

        /**
         * Converts a command-line parameter to a Direction.
         * 
         * @param arg The command-line parameter.
         * @return Converted type or null if invalid.
         */
        static Direction fromArgument(String arg) {
            if (arg.equalsIgnoreCase("-enc")) {
                return ENCRYPT;
            } else if (arg.equalsIgnoreCase("-dec")) {
                return DECRYPT;
            }
            return null;
        }
    }
    
    /**
     * Represents the cipher.
     */
    enum Cipher { 
        DES, TDES, AES; 

        /**
         * Converts a command-line parameter to a Cipher.
         * 
         * @param arg The command-line parameter.
         * @return Converted type or null if invalid.
         */
        static Cipher fromArgument(String arg) {
            if (arg.equalsIgnoreCase("des")) {
                return DES;
            } else if (arg.equalsIgnoreCase("3des")) {
                return TDES;
            } else if (arg.equalsIgnoreCase("aes")) {
                return AES;
            }
            return null;
        }
    }
    
    /**
     * Represents the block cipher mode of operation.
     */
    enum BlockMode { 
        ECB, CBC, CTR; 

        /**
         * Converts a command-line parameter to a BlockMode.
         * 
         * @param arg The command-line parameter.
         * @return Converted type or null if invalid.
         */
        static BlockMode fromArgument(String arg) {
            if (arg.equalsIgnoreCase("ecb")) {
                return ECB;
            } else if (arg.equalsIgnoreCase("cbc")) {
                return CBC;
            } else if (arg.equalsIgnoreCase("ctr")) {
                return CTR;
            }
            return null;
        }
    }
    
    /**
     * Represents the I/O mode.
     */
    enum IOMode { 
        ASCII, HEX, FILE; 

        /**
         * Converts a command-line parameter to an IOMode.
         * 
         * @param arg The command-line parameter.
         * @return Converted type or null if invalid.
         */
        static IOMode fromArgument(String arg) {
            if (arg.equalsIgnoreCase("asc")) {
                return ASCII;
            } else if (arg.equalsIgnoreCase("hex")) {
                return HEX;
            } else if (arg.equalsIgnoreCase("file")) {
                return FILE;
            }
            return null;
        }
    }
}
