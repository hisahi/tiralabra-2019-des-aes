
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
    
    @Test
    public void correctVerifyIVSize() {
        assertTrue(ctr.isValidIVSize(8));
        assertFalse(ctr.isValidIVSize(9));
    }
    
    @Test
    public void testCTRZeroIVOneBlocks() {
        ctr.initEncrypt(ZERO_NONCE);
        
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edata = ctr.process(Arrays.copyOf(data, data.length));
        assertArrayEquals(data, edata); // technically (edata == data ^ ZERO_NONCE ^ [0])?
        
        ctr.finish();
    }
    
    @Test
    public void testCTRNonZeroIVOneBlocks() {
        ctr.initEncrypt(TEST_NONCE);
        
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edata = ctr.process(Arrays.copyOf(data, data.length));
        byte[] expc = new byte[] {0x44, 0x47, 0x46, 0x41, 0x40, 0x43, 0x42, 0x4d}; // data ^ (TEST_NONCE ^ [0])
        assertArrayEquals(expc, edata);
        
        ctr.finish();
    }
    
    @Test
    public void testCTRNonZeroIVTwoBlocks() {
        ctr.initEncrypt(TEST_NONCE);
        
        byte[] data1 = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edat1 = ctr.process(Arrays.copyOf(data1, data1.length));
        byte[] expc1 = new byte[] {0x44, 0x47, 0x46, 0x41, 0x40, 0x43, 0x42, 0x4d}; // data1 ^ (TEST_NONCE ^ [0])
        assertArrayEquals(expc1, edat1);
        
        byte[] data2 = new byte[] {0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31};
        byte[] edat2 = ctr.process(Arrays.copyOf(data2, data2.length));
        byte[] expc2 = new byte[] {0x7f, 0x7e, 0x79, 0x78, 0x7b, 0x7a, 0x65, 0x65}; // data2 ^ (TEST_NONCE ^ [1])
        assertArrayEquals(expc2, edat2);
        
        ctr.finish();
    }
    
    @Test
    public void testCTREncryptDecrypt() {
        ctr.initEncrypt(TEST_NONCE);
        
        byte[] data1 = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edat1 = ctr.process(Arrays.copyOf(data1, data1.length));
        byte[] expc1 = new byte[] {0x44, 0x47, 0x46, 0x41, 0x40, 0x43, 0x42, 0x4d}; // data1 ^ TEST_IV
        assertArrayEquals(expc1, edat1);
        
        ctr.finish();
        ctr.initDecrypt(TEST_NONCE);
        
        byte[] edat2 = ctr.process(Arrays.copyOf(expc1, expc1.length));
        assertArrayEquals(data1, edat2);
        
        ctr.finish();
    }
    
    @Test(expected = IllegalStateException.class)
    public void noInitIllegalState() {
        ctr.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
    }
    
    @Test(expected = IllegalStateException.class)
    public void postFinishIllegalState() {
        ctr.finish();
        ctr.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
    }
    
    @Test(expected = IllegalStateException.class)
    public void twoInitIllegalState() {
        ctr.initEncrypt(ZERO_NONCE);
        ctr.initDecrypt(ZERO_NONCE);
    }
    
    @Test(expected = IllegalStateException.class)
    public void twoFinishIllegalState() {
        ctr.initEncrypt(ZERO_NONCE);
        ctr.finish();
        ctr.finish();
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void wrongBlockSizeIllegalArgument() {
        ctr.initDecrypt(ZERO_NONCE);
        ctr.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    }
}
