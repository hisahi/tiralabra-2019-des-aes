
package com.github.hisahi.tiralabradesaes.keyderiv; 

import com.github.hisahi.tiralabradesaes.Utils;
import com.github.hisahi.tiralabradesaes.hash.HashSHA1;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class HMACFunctionTest {
    private HMACFunction hmac;
    
    @Before
    public void setUp() {
        hmac = new HMACFunction(new HashSHA1());
    }
    
    /**
     * Test case for HMAC SHA-1 with empty key and message. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void hmacSha1Empty() {
        assertEquals("fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",  Utils.convertBytesToHex(hmac.computeHmac(
                     "".getBytes(StandardCharsets.UTF_8), 
                     "".getBytes(StandardCharsets.UTF_8))));
    }
    
    /**
     * Test case for HMAC SHA-1 with a sample key and message. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void hmacSha1Test() {
        assertEquals("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",  Utils.convertBytesToHex(hmac.computeHmac(
                     "key".getBytes(StandardCharsets.UTF_8), 
                     "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8))));
    }
}
