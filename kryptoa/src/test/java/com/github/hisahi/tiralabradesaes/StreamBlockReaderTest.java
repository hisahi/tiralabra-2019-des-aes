package com.github.hisahi.tiralabradesaes;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

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
        assertArrayEquals(new byte[] {0x11, 0x12, 0x13, 0x14, 4, 4, 4, 4}, bis.nextBlock());
        assertEquals(null, bis.nextBlock());
    }
    
    @Test
    public void partialPadding1() throws IOException {
        os.write(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17});
        os.close();
        assertArrayEquals(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 1}, bis.nextBlock());
        assertEquals(null, bis.nextBlock());
    }
    
    @Test
    public void fullPadding() throws IOException {
        os.write(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18});
        os.close();
        assertArrayEquals(new byte[] {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}, bis.nextBlock());
        assertArrayEquals(new byte[] {8, 8, 8, 8, 8, 8, 8, 8}, bis.nextBlock());
        assertEquals(null, bis.nextBlock());
    }
}
