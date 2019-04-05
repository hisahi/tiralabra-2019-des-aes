
package com.github.hisahi.tiralabradesaes.blockmodes; 

import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;

/**
 * Implements the ECB, or Electronic Code Book, block mode of operation.
 * ECB does not modify the plaintext blocks in any way when passing them to 
 * a cipher, meaning that repeating blocks will also be repeating in the
 * resulting stream of ciphertext.
 */
public class BlockModeECB implements IBlockMode {
    
    private IBlockCipher ciph;
    private boolean init = false;

    /**
     * Initializes the ECB block mode with the cipher to call process() with.
     * 
     * @param cipher The cipher to call process() with.
     */
    public BlockModeECB(IBlockCipher cipher) {
        ciph = cipher;
    }
    
    @Override
    public boolean isValidIVSize(int bytes) {
        return true;
    }
    
    private void initBase(byte[] iv) {
        if (init) {
            throw new IllegalStateException("already init");
        }
        init = true;
    }
    
    @Override
    public void initEncrypt(byte[] key, byte[] iv) {
        initBase(iv);
        ciph.initEncrypt(key);
    }
    
    @Override
    public void initDecrypt(byte[] key, byte[] iv) {
        initBase(iv);
        ciph.initDecrypt(key);
    }

    @Override
    public byte[] process(byte[] data) {
        if (!init) {
            throw new IllegalStateException("block mode not initialized");
        }
        if (data.length != ciph.getBlockSizeInBytes()) {
            throw new IllegalArgumentException("wrong block size");
        }
        return ciph.process(data);
    }

    @Override
    public void finish() {
        if (!init) {
            throw new IllegalStateException("already finished");
        }
        init = false;
        ciph.finish();
    }

}
