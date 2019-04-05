
package com.github.hisahi.tiralabradesaes.blockmodes;

import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class BlockModeECBTest {
    
    MockBlockCipher mbc;
    BlockModeECB ecb;
    
    public BlockModeECBTest() {
    }
    
    @Before
    public void setUp() {
        mbc = new MockBlockCipher();
        ecb = new BlockModeECB(mbc);
    }
    
    /**
     * ECB should not apply any extra steps and simply encrypt/decrypt
     * the given block with the cipher.
     */
    @Test
    public void dataGoesThrough() {
        ecb.initEncrypt(new byte[] {0}, null);
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edata = ecb.process(Arrays.copyOf(data, data.length));
        assertArrayEquals(data, edata);
        ecb.finish();
    }
    
    /**
     * process() should raise an exception if the block mode is not initialized.
     */
    @Test(expected = IllegalStateException.class)
    public void noInitIllegalState() {
        ecb.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
    }
    
    /**
     * process() should raise an exception if the block mode has not been
     * initialized after a call to finish().
     */
    @Test(expected = IllegalStateException.class)
    public void postFinishIllegalState() {
        ecb.finish();
        ecb.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
    }
    
    /**
     * The block mode should not allow two initializations without an 
     * intermediate finish().
     */
    @Test(expected = IllegalStateException.class)
    public void twoInitIllegalState() {
        ecb.initEncrypt(new byte[] {0}, null);
        ecb.initDecrypt(new byte[] {0}, null);
    }
    
    /**
     * The block mode should not allow two finish() calls without an
     * intermediate initialization.
     */
    @Test(expected = IllegalStateException.class)
    public void twoFinishIllegalState() {
        ecb.initEncrypt(new byte[] {0}, null);
        ecb.finish();
        ecb.finish();
    }
    
    /**
     * The block mode should not accept plaintext or ciphertext blocks
     * that do not match the block size expected by the cipher.
     */
    @Test(expected = IllegalArgumentException.class)
    public void wrongBlockSizeIllegalArgument() {
        ecb.initDecrypt(new byte[] {0}, null);
        ecb.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    }
}
