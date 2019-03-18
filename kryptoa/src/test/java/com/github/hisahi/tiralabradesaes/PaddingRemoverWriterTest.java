/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.github.hisahi.tiralabradesaes;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author hopea
 */
public class PaddingRemoverWriterTest {
    
    PipedInputStream is;
    PipedOutputStream os;
    PaddingRemoverWriter prw;
    
    @Before
    public void setUp() throws IOException {
        os = new PipedOutputStream();
        is = new PipedInputStream(os);
        prw = new PaddingRemoverWriter(os, 8);
    }

    @Test
    public void noBlocksGiven() throws IOException {
        prw.finish(); os.flush(); os.close();
        assertEquals(-1, is.read());
    }

    @Test
    public void removeFullPadding() throws IOException {
        prw.feedBlock(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
        // full padding block
        prw.feedBlock(new byte[] {8, 8, 8, 8, 8, 8, 8, 8});
        prw.finish(); os.flush(); os.close();
        assertEquals(8, is.read(new byte[8]));
        assertEquals(-1, is.read());
    }

    @Test
    public void removePartialPadding() throws IOException {
        prw.feedBlock(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 2, 2});
        prw.finish(); os.flush(); os.close();
        assertEquals(6, is.read(new byte[8]));
        assertEquals(-1, is.read());
    }
}
