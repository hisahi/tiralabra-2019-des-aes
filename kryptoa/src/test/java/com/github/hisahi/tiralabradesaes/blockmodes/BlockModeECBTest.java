
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
    
    @Test
    public void dataGoesThrough() {
        ecb.initEncrypt(null);
        byte[] data = new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18};
        byte[] edata = ecb.process(Arrays.copyOf(data, data.length));
        assertArrayEquals(data, edata);
        ecb.finish();
    }
    
    @Test(expected = IllegalStateException.class)
    public void noInitIllegalState() {
        ecb.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
    }
    
    @Test(expected = IllegalStateException.class)
    public void postFinishIllegalState() {
        ecb.finish();
        ecb.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
    }
    
    @Test(expected = IllegalStateException.class)
    public void twoInitIllegalState() {
        ecb.initEncrypt(null);
        ecb.initDecrypt(null);
    }
    
    @Test(expected = IllegalStateException.class)
    public void twoFinishIllegalState() {
        ecb.initEncrypt(null);
        ecb.finish();
        ecb.finish();
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void wrongBlockSizeIllegalArgument() {
        ecb.initDecrypt(null);
        ecb.process(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
    }
}
