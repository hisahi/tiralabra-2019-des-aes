
package com.github.hisahi.tiralabradesaes;

import java.io.IOException;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class Base64OutputStreamTest {
    
    Base64OutputStream hos;
    PipedOutputStream pos;
    PipedInputStream pis;
    
    @Before
    public void setUp() throws IOException {
        pis = new PipedInputStream();
        pos = new PipedOutputStream(pis);
        hos = new Base64OutputStream(new PrintStream(pos));
    }
    
    @After
    public void tearDown() throws IOException {
        hos.close();
        pos.close();
        pis.close();
    }
    
    private void testBase64Encode(String b64, String input) throws IOException {
        hos.write(input.getBytes(StandardCharsets.US_ASCII));
        hos.close(); 
        pos.close();
        
        byte[] res = new byte[b64.length()];
        assertEquals(b64.length(), pis.read(res));
        assertArrayEquals(b64.getBytes(StandardCharsets.US_ASCII), res);
    }

    /**
     * Base64 encoding test, verified against known implementation.
     */
    @Test
    public void testBase64Encode_f() throws IOException {
        testBase64Encode("Zg==", "f");
    }

    /**
     * Base64 encoding test, verified against known implementation.
     */
    @Test
    public void testBase64Encode_fo() throws IOException {
        testBase64Encode("Zm8=", "fo");
    }

    /**
     * Base64 encoding test, verified against known implementation.
     */
    @Test
    public void testBase64Encode_foo() throws IOException {
        testBase64Encode("Zm9v", "foo");
    }

    /**
     * Base64 encoding test, verified against known implementation.
     */
    @Test
    public void testBase64Encode_foob() throws IOException {
        testBase64Encode("Zm9vYg==", "foob");
    }

    /**
     * Base64 encoding test, verified against known implementation.
     */
    @Test
    public void testBase64Encode_fooba() throws IOException {
        testBase64Encode("Zm9vYmE=", "fooba");
    }

    /**
     * Base64 encoding test, verified against known implementation.
     */
    @Test
    public void testBase64Encode_foobar() throws IOException {
        testBase64Encode("Zm9vYmFy", "foobar");
    }
}
