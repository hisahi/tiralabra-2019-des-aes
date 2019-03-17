
package com.github.hisahi.tiralabradesaes.blockmodes; 

import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;

/**
 * Implements the ECB, or Electronic Code Book, block mode of operation.
 * ECB does not modify the plaintext blocks in any way when passing them to 
 * a cipher, meaning that repeating blocks will also be repeating in the
 * resulting stream of ciphertext.
 */
public class BlockModeECB implements IBlockMode {
    
    IBlockCipher ciph;
    boolean init = false;

    /**
     * Initializes the ECB block mode with the cipher to call process() with.
     * 
     * @param cipher The cipher to call process() with.
     */
    public BlockModeECB(IBlockCipher cipher) {
        ciph = cipher;
    }
    
    private void initBase(byte[] iv) {
        if (init) {
            throw new IllegalStateException("already init");
        }
        init = true;
    }
    
    @Override
    public void initEncrypt(byte[] iv) {
        initBase(iv);
    }
    
    @Override
    public void initDecrypt(byte[] iv) {
        initBase(iv);
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
    }

}
