
package com.github.hisahi.tiralabradesaes; 

import com.github.hisahi.tiralabradesaes.blockmodes.BlockModeCBC;
import com.github.hisahi.tiralabradesaes.blockmodes.BlockModeCTR;
import com.github.hisahi.tiralabradesaes.blockmodes.BlockModeECB;
import com.github.hisahi.tiralabradesaes.blockmodes.IBlockMode;
import com.github.hisahi.tiralabradesaes.ciphers.CipherAES;
import com.github.hisahi.tiralabradesaes.ciphers.CipherDES;
import com.github.hisahi.tiralabradesaes.ciphers.CipherTripleDES;
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;

class OperationMode {
    private Direction direction;
    private Cipher cipher;
    private BlockMode blockmode;
    private IOMode iomode;
    private String key_str;
    private String iv_str;
    private String input;
    private String output;
    
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
    
    Cipher getCipherType() {
        return cipher;
    }
    
    BlockMode getBlockModeType() {
        return blockmode;
    }
    
    IOMode getIOMode() {
        return iomode;
    }
    
    Direction getDirection() {
        return direction;
    }
    
    String getInputString() {
        return input;
    }
    
    String getOutputString() {
        return output;
    }

    IBlockCipher getCipher() {
        switch (cipher) {
            case DES:   return new CipherDES();
            case TDES:  return new CipherTripleDES();
            case AES:   return new CipherAES();
        }
        return null;
    }

    IBlockMode getBlockMode(IBlockCipher ciph) {
        switch (blockmode) {
            case ECB:   return new BlockModeECB(ciph);
            case CBC:   return new BlockModeCBC(ciph);
            case CTR:   return new BlockModeCTR(ciph);
        }
        return null;
    }

    byte[] getKey() {
        return Utils.convertToHex(key_str);
    }

    byte[] getIV() {
        return Utils.convertToHex(iv_str);
    }
    
    enum Direction { 
        ENCRYPT, DECRYPT;

        static Direction fromArgument(String arg) {
            if (arg.equalsIgnoreCase("-enc")) {
                return ENCRYPT;
            } else if (arg.equalsIgnoreCase("-dec")) {
                return DECRYPT;
            }
            return null;
        }
    }
    enum Cipher { 
        DES, TDES, AES; 

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
    enum BlockMode { 
        ECB, CBC, CTR; 

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
    enum IOMode { 
        ASCII, HEX, FILE; 

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
