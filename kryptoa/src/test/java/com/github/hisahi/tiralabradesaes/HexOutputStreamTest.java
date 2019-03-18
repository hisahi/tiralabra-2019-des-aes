
package com.github.hisahi.tiralabradesaes;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author hopea
 */
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

    @Test
    public void testHexEncode() throws IOException {
        hos.write(0x27);
        assertEquals('2', pis.read());
        assertEquals('7', pis.read());
    }

    @Test
    public void testHexNegative() throws IOException {
        hos.write(0x91);
        assertEquals('9', pis.read());
        assertEquals('1', pis.read());
    }
}
