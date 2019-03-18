
package com.github.hisahi.tiralabradesaes.blockmodes;

import java.util.Arrays;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class BlockModeCBCTest {
    
    private static final byte[] ZERO_IV = new byte[] {0, 0, 0, 0, 0, 0, 0, 0};
    private static final byte[] TEST_IV = new byte[] {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    
    MockBlockCipher mbc;
    BlockModeCBC cbc;
    
    public BlockModeCBCTest() {
    }
    
    @Before
    public void setUp() {
        mbc = new MockBlockCipher();
        cbc = new BlockModeCBC(mbc);
    }
    
    @Test
    public void correctVerifyIVSize() {
        assertTrue(cbc.isValidIVSize(8));
        assertFalse(cbc.isValidIVSize(9));
    }
    
    @Test
    public void testCBCZeroIVOneBlocks() {
        cbc.initEncrypt(ZERO_IV);
        
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edata = cbc.process(Arrays.copyOf(data, data.length));
        assertArrayEquals(data, edata);
        
        cbc.finish();
    }
    
    @Test
    public void testCBCNonZeroIVOneBlocks() {
        cbc.initEncrypt(TEST_IV);
        
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edata = cbc.process(Arrays.copyOf(data, data.length));
        byte[] expc = new byte[] {0x44, 0x47, 0x46, 0x41, 0x40, 0x43, 0x42, 0x4d}; // data ^ TEST_IV
        assertArrayEquals(expc, edata);
        
        cbc.finish();
    }
    
    @Test
    public void testCBCNonZeroIVTwoBlocks() {
        cbc.initEncrypt(TEST_IV);
        
        byte[] data1 = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edat1 = cbc.process(Arrays.copyOf(data1, data1.length));
        byte[] expc1 = new byte[] {0x44, 0x47, 0x46, 0x41, 0x40, 0x43, 0x42, 0x4d}; // data1 ^ TEST_IV
        assertArrayEquals(expc1, edat1);
        
        byte[] data2 = new byte[] {0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31};
        byte[] edat2 = cbc.process(Arrays.copyOf(data2, data2.length));
        byte[] expc2 = new byte[] {0x6e, 0x6c, 0x6a, 0x6c, 0x6e, 0x6c, 0x72, 0x7c}; // data2 ^ expc1
        assertArrayEquals(expc2, edat2);
        
        cbc.finish();
    }
    
    @Test
    public void testCBCEncryptDecrypt() {
        cbc.initEncrypt(TEST_IV);
        
        byte[] data1 = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edat1 = cbc.process(Arrays.copyOf(data1, data1.length));
        byte[] expc1 = new byte[] {0x44, 0x47, 0x46, 0x41, 0x40, 0x43, 0x42, 0x4d}; // data1 ^ TEST_IV
        assertArrayEquals(expc1, edat1);
        
        cbc.finish();
        cbc.initDecrypt(TEST_IV);
        
        byte[] edat2 = cbc.process(Arrays.copyOf(expc1, expc1.length));
        assertArrayEquals(data1, edat2);
        
        cbc.finish();
    }
    
    @Test(expected = IllegalStateException.class)
    public void noInitIllegalState() {
        cbc.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
    }
    
    @Test(expected = IllegalStateException.class)
    public void postFinishIllegalState() {
        cbc.finish();
        cbc.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
    }
    
    @Test(expected = IllegalStateException.class)
    public void twoInitIllegalState() {
        cbc.initEncrypt(ZERO_IV);
        cbc.initDecrypt(ZERO_IV);
    }
    
    @Test(expected = IllegalStateException.class)
    public void twoFinishIllegalState() {
        cbc.initEncrypt(ZERO_IV);
        cbc.finish();
        cbc.finish();
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void wrongBlockSizeIllegalArgument() {
        cbc.initDecrypt(ZERO_IV);
        cbc.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    }
}
