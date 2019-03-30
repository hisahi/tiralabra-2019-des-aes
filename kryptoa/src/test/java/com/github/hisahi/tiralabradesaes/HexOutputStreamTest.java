
package com.github.hisahi.tiralabradesaes;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class HexOutputStreamTest {
    
    HexOutputStream hos;
    PipedOutputStream pos;
    PipedInputStream pis;
    
    @Before
    public void setUp() throws IOException {
        pis = new PipedInputStream();
        pos = new PipedOutputStream(pis);
        hos = new HexOutputStream(new PrintStream(pos));
    }
    
    @After
    public void tearDown() throws IOException {
        hos.close();
        pos.close();
        pis.close();
    }

    /**
     * Simple test for a single byte that should properly be encoded into
     * two hex digits.
     */
    @Test
    public void testHexEncode() throws IOException {
        hos.write(0x27);
        assertEquals('2', pis.read());
        assertEquals('7', pis.read());
    }

    /**
     * Simple test for a negative byte that should properly be encoded into
     * two hex digits. Java does not have unsigned types which makes it
     * easy to incorporate such mistakes.
     */
    @Test
    public void testHexNegative() throws IOException {
        hos.write(0x91);
        assertEquals('9', pis.read());
        assertEquals('1', pis.read());
    }
}
