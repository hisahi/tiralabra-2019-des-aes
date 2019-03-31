
package com.github.hisahi.tiralabradesaes.keyderiv;

import com.github.hisahi.tiralabradesaes.Utils;
import com.github.hisahi.tiralabradesaes.hash.HashSHA1;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class KeyDerivPBKDF2Test {
    
    KeyDerivPBKDF2 kdf;
    
    @Before
    public void setUp() {
        kdf = new KeyDerivPBKDF2(new HMACFunction(new HashSHA1()), 1000);
    }

    /**
     * Simple test for PBKDF2.  The result has been tested against 
     * an implementation known to work correctly.
     */
    @Test
    public void testPBKDF2() {
        byte[] key = new byte[16];
        kdf.deriveKey(key, "eBkXQTfuBqp'cTcar&g*".getBytes(StandardCharsets.UTF_8), 
                Utils.convertHexToBytes("a009c1a485912c6ae630d3e744240b04"));
        assertEquals("17eb4014c8c461c300e9b61518b9a18b", Utils.convertBytesToHex(key));
    }
}
