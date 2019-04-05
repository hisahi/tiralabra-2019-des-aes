
package com.github.hisahi.tiralabradesaes.blockmodes;

import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class BlockModeCTRTest {
    
    private static final byte[] ZERO_NONCE = new byte[] {0, 0, 0, 0, 0, 0, 0, 0};
    private static final byte[] TEST_NONCE = new byte[] {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    
    MockBlockCipher mbc;
    BlockModeCTR ctr;
    
    public BlockModeCTRTest() {
    }
    
    @Before
    public void setUp() {
        mbc = new MockBlockCipher();
        ctr = new BlockModeCTR(mbc);
    }
    
    /**
     * Only 8-byte 64-bit IVs should be valid (because the underlying
     * mock encryption algorithm uses 8-byte 64-bit blocks).
     */
    @Test
    public void correctVerifyIVSize() {
        assertTrue(ctr.isValidIVSize(8));
        assertFalse(ctr.isValidIVSize(9));
    }
    
    /**
     * Testing CTR encryption with one block and zero IV/nonce.
     */
    @Test
    public void testCTRZeroIVOneBlocks() {
        ctr.initEncrypt(new byte[] {0}, ZERO_NONCE);
        
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 
                                  0x15, 0x16, 0x17, 0x18};
        byte[] edata = ctr.process(Arrays.copyOf(data, data.length));
        assertArrayEquals(data, edata); // technically (edata == data ^ ZERO_NONCE ^ [0])?
        
        ctr.finish();
    }
    
    /**
     * Testing CTR encryption with one block and non-zero IV/nonce. The
     * IV/nonce should be XORed into the resulting ciphertext block.
     */
    @Test
    public void testCTRNonZeroIVOneBlocks() {
        ctr.initEncrypt(new byte[] {0}, TEST_NONCE);
        
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 
                                  0x15, 0x16, 0x17, 0x18};
        byte[] edata = ctr.process(Arrays.copyOf(data, data.length));
        byte[] expc = new byte[] {0x44, 0x47, 0x46, 0x41, 
                                  0x40, 0x43, 0x42, 0x4d}; // data ^ (TEST_NONCE ^ [0])
        assertArrayEquals(expc, edata);
        
        ctr.finish();
    }
    
    /**
     * Testing CTR encryption with two blocks and non-zero IV/nonce. The
     * IV/nonce should be XORed into the resulting ciphertext blocks. The
     * second block should also have been XORed with an incremented counter.
     */
    @Test
    public void testCTRNonZeroIVTwoBlocks() {
        ctr.initEncrypt(new byte[] {0}, TEST_NONCE);
        
        byte[] data1 = new byte[] {0x11, 0x12, 0x13, 0x14, 
                                   0x15, 0x16, 0x17, 0x18};
        byte[] edat1 = ctr.process(Arrays.copyOf(data1, data1.length));
        byte[] expc1 = new byte[] {0x44, 0x47, 0x46, 0x41,  // data1 ^ ([0] ^
                                   0x40, 0x43, 0x42, 0x4d}; // TEST_NONCE)
        assertArrayEquals(expc1, edat1);
        
        byte[] data2 = new byte[] {0x2a, 0x2b, 0x2c, 0x2d, 
                                   0x2e, 0x2f, 0x30, 0x31};
        byte[] edat2 = ctr.process(Arrays.copyOf(data2, data2.length));
        byte[] expc2 = new byte[] {0x7f, 0x7e, 0x79, 0x78,  // data1 ^ ([1] ^
                                   0x7b, 0x7a, 0x65, 0x65}; // TEST_NONCE)
        assertArrayEquals(expc2, edat2);
        
        ctr.finish();
    }
    
    /**
     * CTR as well as other block modes should be able to encrypt any input
     * back into its original form.
     */
    @Test
    public void testCTREncryptDecrypt() {
        ctr.initEncrypt(new byte[] {0}, TEST_NONCE);
        
        byte[] data1 = new byte[] {0x11, 0x12, 0x13, 0x14, 
                                   0x15, 0x16, 0x17, 0x18};
        byte[] edat1 = ctr.process(Arrays.copyOf(data1, data1.length));
        byte[] expc1 = new byte[] {0x44, 0x47, 0x46, 0x41, 
                                   0x40, 0x43, 0x42, 0x4d}; // data1 ^ TEST_IV
        assertArrayEquals(expc1, edat1);
        
        ctr.finish();
        ctr.initDecrypt(new byte[] {0}, TEST_NONCE);
        
        byte[] edat2 = ctr.process(Arrays.copyOf(expc1, expc1.length));
        assertArrayEquals(data1, edat2);
        
        ctr.finish();
    }
    
    /**
     * process() should raise an exception if the block mode is not initialized.
     */
    @Test(expected = IllegalStateException.class)
    public void noInitIllegalState() {
        ctr.process(new byte[] {0x11, 0x12, 0x13, 0x14, 
                                0x15, 0x16, 0x17, 0x18});
    }
    
    /**
     * process() should raise an exception if the block mode has not been
     * initialized after a call to finish().
     */
    @Test(expected = IllegalStateException.class)
    public void postFinishIllegalState() {
        ctr.finish();
        ctr.process(new byte[] {0x11, 0x12, 0x13, 0x14, 
                                0x15, 0x16, 0x17, 0x18});
    }
    
    /**
     * The block mode should not allow two initializations without an 
     * intermediate finish().
     */
    @Test(expected = IllegalStateException.class)
    public void twoInitIllegalState() {
        ctr.initEncrypt(new byte[] {0}, ZERO_NONCE);
        ctr.initDecrypt(new byte[] {0}, ZERO_NONCE);
    }
    
    /**
     * The block mode should not allow two finish() calls without an
     * intermediate initialization.
     */
    @Test(expected = IllegalStateException.class)
    public void twoFinishIllegalState() {
        ctr.initEncrypt(new byte[] {0}, ZERO_NONCE);
        ctr.finish();
        ctr.finish();
    }
    
    /**
     * The block mode should not accept plaintext or ciphertext blocks
     * that do not match the block size expected by the cipher.
     */
    @Test(expected = IllegalArgumentException.class)
    public void wrongBlockSizeIllegalArgument() {
        ctr.initDecrypt(new byte[] {0}, ZERO_NONCE);
        ctr.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    }
    
    /**
     * The block mode should not accept IV blocks of the wrong size
     * when initializing.
     */
    @Test(expected = IllegalArgumentException.class)
    public void wrongIVSizeIllegalArgument() {
        ctr.initDecrypt(new byte[] {0}, 
                new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    }
}
