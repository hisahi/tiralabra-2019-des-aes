
package com.github.hisahi.tiralabradesaes.keyderiv; 

import com.github.hisahi.tiralabradesaes.Utils;
import com.github.hisahi.tiralabradesaes.hash.HashSHA1;
import com.github.hisahi.tiralabradesaes.hash.HashSHA2_256;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class HMACFunctionTest {
    private HMACFunction hmac;
    
    /**
     * Test case for HMAC SHA-1 with empty key and message. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void hmacSha1Empty() {
        hmac = new HMACFunction(new HashSHA1());
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
        hmac = new HMACFunction(new HashSHA1());
        assertEquals("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",  Utils.convertBytesToHex(hmac.computeHmac(
                     "key".getBytes(StandardCharsets.UTF_8), 
                     "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8))));
    }
    
    /**
     * Test case for HMAC SHA-256 with a sample key and message. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void hmacSha2_256Empty() {
        hmac = new HMACFunction(new HashSHA2_256());
        assertEquals("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",  Utils.convertBytesToHex(hmac.computeHmac(
                     "key".getBytes(StandardCharsets.UTF_8), 
                     "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8))));
    }
}
