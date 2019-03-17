/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.hisahi.tiralabradesaes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author hopea
 */
public class StreamBlockReaderTest {
    
    PipedOutputStream os;
    PipedInputStream is;
    StreamBlockReader bis;
    
    public StreamBlockReaderTest() {
    }
    
    @Before
    public void setUp() throws IOException {
        os = new PipedOutputStream();
        is = new PipedInputStream(os);
        bis = new StreamBlockReader(is, 8);
    }
    
    @Test
    public void partialPadding4() throws IOException {
        os.write(new byte[] {0x11, 0x12, 0x13, 0x14});
        os.close();
        Assert.assertArrayEquals(new byte[] {0x11, 0x12, 0x13, 0x14, 4, 4, 4, 4}, bis.nextBlock());
        Assert.assertEquals(null, bis.nextBlock());
    }
    
    @Test
    public void partialPadding1() throws IOException {
        os.write(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
        os.close();
        Assert.assertArrayEquals(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 1}, bis.nextBlock());
        Assert.assertEquals(null, bis.nextBlock());
    }
    
    @Test
    public void fullPadding() throws IOException {
        os.write(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
        os.close();
        Assert.assertArrayEquals(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}, bis.nextBlock());
        Assert.assertArrayEquals(new byte[] {8, 8, 8, 8, 8, 8, 8, 8}, bis.nextBlock());
        Assert.assertEquals(null, bis.nextBlock());
    }
}
