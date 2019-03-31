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
    
    /**
     * A stream with only 4 bytes padded to 8 bytes should include 4 bytes
     * with the value of 4 at the end of the stream, making it 8 bytse in total.
     * 
     * @throws IOException Only happens if the piped streams fail for whatever
     * reason.
     */
    @Test
    public void partialPadding4() throws IOException {
        os.write(Utils.convertHexToBytes("11121314"));
        os.close();
        assertEquals("1112131404040404", 
                     Utils.convertBytesToHex(bis.nextBlock()));
        assertEquals(null, bis.nextBlock());
    }
    
    /**
     * A stream with only 7 bytes padded to 8 bytes should include 1 byte
     * with the value of 1 at the end of the stream, making it 8 bytse in total.
     * 
     * @throws IOException Only happens if the piped streams fail for whatever
     * reason.
     */
    @Test
    public void partialPadding1() throws IOException {
        os.write(Utils.convertHexToBytes("11121314151617"));
        os.close();
        assertEquals("1112131415161701", 
                     Utils.convertBytesToHex(bis.nextBlock()));
        assertEquals(null, bis.nextBlock());
    }
    
    /**
     * A block with 8 bytes in total should not receive padding, but the end
     * of the stream there should be a full padding block, 8 bytes of value 8.
     * 
     * @throws IOException Only happens if the piped streams fail for whatever
     * reason.
     */
    @Test
    public void fullPadding() throws IOException {
        os.write(Utils.convertHexToBytes("1112131415161718"));
        os.close();
        assertEquals("1112131415161718", 
                     Utils.convertBytesToHex(bis.nextBlock()));
        assertEquals("0808080808080808", 
                     Utils.convertBytesToHex(bis.nextBlock()));
        assertEquals(null, bis.nextBlock());
    }
}
