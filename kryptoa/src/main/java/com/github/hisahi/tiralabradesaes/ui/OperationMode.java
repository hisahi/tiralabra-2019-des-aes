
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
import java.nio.charset.StandardCharsets;

/**
 * A class for representing the mode of operation of the program as given
 * by command-line parameters.
 */
class OperationMode {
    private final Direction direction;
    private final IOMode iomode;
    private final KeyMode keymode;
    private final String key_str;
    private final String iv_str;
    private final String input;
    private final String output;
    private Cipher cipher;
    private BlockMode blockmode;
    
    public OperationMode(Direction dir, Cipher ciph, BlockMode bm, IOMode io, 
            KeyMode km, String k, String nonce, String in, String out) {
        direction = dir;
        cipher = ciph;
        blockmode = bm;
        iomode = io;
        keymode = km;
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
     * Gets the chosen key mode (either hex key, password or key file).
     * 
     * @return The key mode chosen via parameters.
     */
    KeyMode getKeyMode() {
        return keymode;
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
     * Gets the given key parameter as a string. Used if the key parameter
     * turns out to not be hex or a password, meaning that it has to be
     * a file path.
     * 
     * @return The key parameter given.
     */
    String getKeyString() {
        return key_str;
    }
    
    /**
     * Gets the password used to derive a key, if the given key parameter
     * was a password. Password must begin with a quote and end with one
     * when given as a parameter; these quotes are not considered part
     * of the password.
     * 
     * @return The password, or null if a password was not given.
     */
    byte[] getKeyPassword() {
        return key_str.substring(1, key_str.length() - 1)
                    .getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Returns the key as a byte array, converted from the given hex string.
     * If the hex string given was invalid, this will return null.
     * 
     * @return Key given as a hex string parameter or null if invalid.
     */
    byte[] getKeyHex() {
        return Utils.convertHexToBytes(key_str);
    }
    
    /**
     * Whether an IV was given in the first place. If false, isIVRandom()
     * will return false and getIVHex() will return null.
     * 
     * @return Whether an IV was given as a parameter.
     */
    boolean wasIVGiven() {
        return iv_str != null && !iv_str.isEmpty();
    }
    
    /**
     * Whether to generate a random IV; occurs when - is given as the IV.
     * If this is true, the calling code is responsible for generating the
     * IV, and getIVHex() will return nothing useful.
     * 
     * @return Whether to generate a random IV.
     */
    boolean isIVRandom() {
        return iv_str.equalsIgnoreCase("-");
    }

    /**
     * Returns the IV as a byte array, converted from the given hex string.
     * If the hex string given was invalid, this will return null.
     * For ECB mode, this will return an empty byte array, not null.
     * 
     * @return IV given as a hex string parameter or null if invalid.
     */
    byte[] getIVHex() {
        return Utils.convertHexToBytes(iv_str);
    }
    
    /**
     * Changes the cipher used by this OperationNode.
     * 
     * @param ciph The new Cipher to use.
     */
    void setCipher(Cipher ciph) {
        cipher = ciph;
    }
    
    /**
     * Changes the block mode used by this OperationNode.
     * 
     * @param bm The new BlockMode to use.
     */
    void setBlockMode(BlockMode bm) {
        blockmode = bm;
    }
    
    /**
     * Represents the direction of operation.
     */
    enum Direction { 
        ENCRYPT, DECRYPT, TEST;

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
            } else if (arg.equalsIgnoreCase("-test")) {
                return TEST;
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
        ASCII, HEX, BASE64, FILE; 

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
            } else if (arg.equalsIgnoreCase("b64")) {
                return BASE64;
            } else if (arg.equalsIgnoreCase("file")) {
                return FILE;
            }
            return null;
        }
    }
    
    /**
     * Represents the key mode.
     */
    enum KeyMode { 
        HEX, PASS, FILE; 

        /**
         * Converts a command-line parameter to a KeyMode.
         * 
         * @param arg The command-line parameter.
         * @return Converted type or null if invalid.
         */
        static KeyMode fromArgument(String arg) {
            if (arg.equalsIgnoreCase("-key")) {
                return HEX;
            } else if (arg.equalsIgnoreCase("-pass")) {
                return PASS;
            } else if (arg.equalsIgnoreCase("-kfile")) {
                return FILE;
            }
            return null;
        }
    }
}
