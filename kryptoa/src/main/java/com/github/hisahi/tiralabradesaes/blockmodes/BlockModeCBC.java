
package com.github.hisahi.tiralabradesaes.blockmodes; 

import com.github.hisahi.tiralabradesaes.Utils;
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;
import java.util.Arrays;

/**
 * Implements the CBC, or Cipher Block Chaining, block mode of operation.
 * CBC XORs the blocks of plaintext with the earlier block of ciphertext.
 */
public class BlockModeCBC implements IBlockMode {
    
    private IBlockCipher ciph;
    private boolean init = false;
    private boolean encrypting = false;
    private byte[] lastBlock;
    private byte[] cb;

    /**
     * Initializes the CBC block mode with the cipher to call process() with.
     * 
     * @param cipher The cipher to call process() with.
     */
    public BlockModeCBC(IBlockCipher cipher) {
        ciph = cipher;
        lastBlock = new byte[ciph.getBlockSizeInBytes()];
        cb = new byte[0];
    }
    
    @Override
    public boolean isValidIVSize(int bytes) {
        return bytes == ciph.getBlockSizeInBytes();
    }
    
    private void initBase(byte[] iv) {
        if (iv.length != lastBlock.length) {
            throw new IllegalArgumentException("wrong size for IV");
        }
        if (init) {
            throw new IllegalStateException("already init");
        }
        init = true;
        // init lastBlock
        System.arraycopy(iv, 0, lastBlock, 0, lastBlock.length);
    }
    
    @Override
    public void initEncrypt(byte[] iv) {
        initBase(iv);
        encrypting = true;
    }
    
    @Override
    public void initDecrypt(byte[] iv) {
        initBase(iv);
        encrypting = false;
    }

    @Override
    public byte[] process(byte[] data) {
        if (!init) {
            throw new IllegalStateException("block mode not initialized");
        }
        if (data.length != ciph.getBlockSizeInBytes()) {
            throw new IllegalArgumentException("wrong block size");
        }
        
        if (encrypting) {
            // XOR with lastBlock
            for (int i = 0; i < data.length; ++i) {
                data[i] ^= lastBlock[i];
            }
            
            // encrypt
            cb = ciph.process(data);
            
            // new lastBlock init
            System.arraycopy(cb, 0, lastBlock, 0, lastBlock.length);
        } else {
            // decrypt
            cb = ciph.process(Arrays.copyOf(data, data.length));
            
            // XOR with lastBlock
            for (int i = 0; i < cb.length; ++i) {
                cb[i] ^= lastBlock[i];
            }
            
            // new lastBlock init
            System.arraycopy(data, 0, lastBlock, 0, lastBlock.length);
        }
        return cb;
    }

    @Override
    public void finish() {
        if (!init) {
            throw new IllegalStateException("already finished");
        }
        init = false;
        // destroy lastBlock & cb
        Utils.destroyArray(lastBlock);
        Utils.destroyArray(cb); 
    }

}
