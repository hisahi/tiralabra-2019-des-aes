
package com.github.hisahi.tiralabradesaes.blockmodes; 

import com.github.hisahi.tiralabradesaes.Utils;
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;
import java.util.Arrays;

/**
 * Implements the CTR, or Counter, block mode of operation.
 * CTR turns the block cipher into a stream cipher, using a XOR of
 * the IV and an incrementing counter as the "plaintext" and XORing the result
 * with the real plaintext.
 */
public class BlockModeCTR implements IBlockMode {
    
    private IBlockCipher ciph;
    private boolean init = false;
    private byte[] ctriv; // all three are the same length
    private byte[] counter;
    private byte[] tempbuf;
    private byte[] cb;

    /**
     * Initializes the CTR block mode with the cipher to call process() with.
     * 
     * @param cipher The cipher to call process() with.
     */
    public BlockModeCTR(IBlockCipher cipher) {
        ciph = cipher;
        ctriv = new byte[ciph.getBlockSizeInBytes()];
        counter = new byte[ciph.getBlockSizeInBytes()];
        tempbuf = new byte[ciph.getBlockSizeInBytes()];
        cb = new byte[0];
    }
    
    @Override
    public boolean isValidIVSize(int bytes) {
        return bytes == ciph.getBlockSizeInBytes();
    }
    
    private void initBase(byte[] iv) {
        if (init) {
            throw new IllegalStateException("already init");
        }
        init = true;
        assert iv.length == ctriv.length;
        // init IV
        System.arraycopy(iv, 0, ctriv, 0, iv.length);
        // init counter, tempbuf
        Arrays.fill(counter, (byte) 0);
        Arrays.fill(tempbuf, (byte) 0);
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

        // create tempbuf = IV ^ CTR
        for (int i = 0; i < ctriv.length; ++i) {
            tempbuf[i] = (byte) (ctriv[i] ^ counter[i]);
        }
        
        // encrypt IV ^ CTR
        cb = ciph.process(tempbuf);
        
        // XOR with plaintext data
        for (int i = 0; i < cb.length; ++i) {
            cb[i] ^= data[i];
        }
        
        incrementCounter();
        return cb;
    }

    @Override
    public void finish() {
        if (!init) {
            throw new IllegalStateException("already finished");
        }
        init = false;
        // destroy IV, counter, tempbuf
        Utils.destroyArray(ctriv);
        Arrays.fill(counter, (byte) 0);
        Arrays.fill(tempbuf, (byte) 0);
        Arrays.fill(cb, (byte) 0);
    }

    /**
     * Increments the internal counter by one.
     */
    private void incrementCounter() {
        for (int i = counter.length - 1; i >= 0; --i) {
            // increment last byte, but if it wraps around, keep going (ripple)
            if (++counter[i] != 0) {
                break;
            }
        }
    }

}
