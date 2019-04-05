
package com.github.hisahi.tiralabradesaes.blockmodes;

import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class BlockModeCBCTest {
    
    private static final byte[] ZERO_IV = new byte[] 
                {0, 0, 0, 0, 0, 0, 0, 0};
    private static final byte[] TEST_IV = new byte[] 
                {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    
    MockBlockCipher mbc;
    BlockModeCBC cbc;
    
    public BlockModeCBCTest() {
    }
    
    @Before
    public void setUp() {
        mbc = new MockBlockCipher();
        cbc = new BlockModeCBC(mbc);
    }
    
    /**
     * Only 8-byte 64-bit IVs should be valid (because the underlying
     * mock encryption algorithm uses 8-byte 64-bit blocks).
     */
    @Test
    public void correctVerifyIVSize() {
        assertTrue(cbc.isValidIVSize(8));
        assertFalse(cbc.isValidIVSize(9));
    }
    
    /**
     * Testing CBC encryption with one block and zero IV.
     */
    @Test
    public void testCBCZeroIVOneBlocks() {
        cbc.initEncrypt(new byte[] {0}, ZERO_IV);
        
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 
                                  0x15, 0x16, 0x17, 0x18};
        byte[] edata = cbc.process(Arrays.copyOf(data, data.length));
        assertArrayEquals(data, edata);
        
        cbc.finish();
    }
    
    /**
     * Testing CBC encryption with one block and non-zero IV. The IV should
     * be XORed into the resulting ciphertext block.
     */
    @Test
    public void testCBCNonZeroIVOneBlocks() {
        cbc.initEncrypt(new byte[] {0}, TEST_IV);
        
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14,  
                                  0x15, 0x16, 0x17, 0x18};
        byte[] edata = cbc.process(Arrays.copyOf(data, data.length));
        byte[] expc = new byte[] {0x44, 0x47, 0x46, 0x41, 
                                  0x40, 0x43, 0x42, 0x4d}; // data ^ TEST_IV
        assertArrayEquals(expc, edata);
        
        cbc.finish();
    }
    
    /**
     * Testing CBC encryption with two blocks and non-zero IV. The IV should
     * be XORed into the first resulting ciphertext block, while the second
     * encrypted block should depend on the result of the last block.
     */
    @Test
    public void testCBCNonZeroIVTwoBlocks() {
        cbc.initEncrypt(new byte[] {0}, TEST_IV);
        
        byte[] data1 = new byte[] {0x11, 0x12, 0x13, 0x14, 
                                   0x15, 0x16, 0x17, 0x18};
        byte[] edat1 = cbc.process(Arrays.copyOf(data1, data1.length));
        byte[] expc1 = new byte[] {0x44, 0x47, 0x46, 0x41, 
                                   0x40, 0x43, 0x42, 0x4d}; // data1 ^ TEST_IV
        assertArrayEquals(expc1, edat1);
        
        byte[] data2 = new byte[] {0x2a, 0x2b, 0x2c, 0x2d, 
                                   0x2e, 0x2f, 0x30, 0x31};
        byte[] edat2 = cbc.process(Arrays.copyOf(data2, data2.length));
        byte[] expc2 = new byte[] {0x6e, 0x6c, 0x6a, 0x6c, 
                                   0x6e, 0x6c, 0x72, 0x7c}; // data2 ^ expc1
        assertArrayEquals(expc2, edat2);
        
        cbc.finish();
    }
    
    /**
     * CBC as well as other block modes should be able to encrypt any input
     * back into its original form.
     */
    @Test
    public void testCBCEncryptDecrypt() {
        cbc.initEncrypt(new byte[] {0}, TEST_IV);
        
        byte[] data1 = new byte[] {0x11, 0x12, 0x13, 0x14, 
                                   0x15, 0x16, 0x17, 0x18};
        byte[] edat1 = cbc.process(Arrays.copyOf(data1, data1.length));
        byte[] expc1 = new byte[] {0x44, 0x47, 0x46, 0x41, 
                                   0x40, 0x43, 0x42, 0x4d}; // data1 ^ TEST_IV
        assertArrayEquals(expc1, edat1);
        
        cbc.finish();
        cbc.initDecrypt(new byte[] {0}, TEST_IV);
        
        byte[] edat2 = cbc.process(Arrays.copyOf(expc1, expc1.length));
        assertArrayEquals(data1, edat2);
        
        cbc.finish();
    }
    
    /**
     * process() should raise an exception if the block mode is not initialized.
     */
    @Test(expected = IllegalStateException.class)
    public void noInitIllegalState() {
        cbc.process(new byte[] {0x11, 0x12, 0x13, 0x14, 
                                0x15, 0x16, 0x17, 0x18});
    }
    
    /**
     * process() should raise an exception if the block mode has not been
     * initialized after a call to finish().
     */
    @Test(expected = IllegalStateException.class)
    public void postFinishIllegalState() {
        cbc.finish();
        cbc.process(new byte[] {0x11, 0x12, 0x13, 0x14, 
                                0x15, 0x16, 0x17, 0x18});
    }
    
    /**
     * The block mode should not allow two initializations without an 
     * intermediate finish().
     */
    @Test(expected = IllegalStateException.class)
    public void twoInitIllegalState() {
        cbc.initEncrypt(new byte[] {0}, ZERO_IV);
        cbc.initDecrypt(new byte[] {0}, ZERO_IV);
    }
    
    /**
     * The block mode should not allow two finish() calls without an
     * intermediate initialization.
     */
    @Test(expected = IllegalStateException.class)
    public void twoFinishIllegalState() {
        cbc.initEncrypt(new byte[] {0}, ZERO_IV);
        cbc.finish();
        cbc.finish();
    }
    
    /**
     * The block mode should not accept plaintext or ciphertext blocks
     * that do not match the block size expected by the cipher.
     */
    @Test(expected = IllegalArgumentException.class)
    public void wrongBlockSizeIllegalArgument() {
        cbc.initDecrypt(new byte[] {0}, ZERO_IV);
        cbc.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    }
    
    /**
     * The block mode should not accept IV blocks of the wrong size
     * when initializing.
     */
    @Test(expected = IllegalArgumentException.class)
    public void wrongIVSizeIllegalArgument() {
        cbc.initDecrypt(new byte[] {0}, 
                new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    }
}
