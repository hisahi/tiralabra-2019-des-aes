
package com.github.hisahi.tiralabradesaes.hash;

import com.github.hisahi.tiralabradesaes.Utils;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class HashSHA2_224Test {
    
    private HashSHA2_224 sha2;
    
    @Before
    public void setUp() {
        sha2 = new HashSHA2_224();
    }

    /**
     * Test case for SHA2-256 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test0_224() {
        assertEquals("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", Utils.convertBytesToHex(sha2.computeHash(
                     "".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-256 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test1_224() {
        assertEquals("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", Utils.convertBytesToHex(sha2.computeHash(
                     "abc".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-256 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test2_224() {
        assertEquals("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525", Utils.convertBytesToHex(sha2.computeHash(
                     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-256 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test3_224() {
        assertEquals("c97ca9a559850ce97a04a96def6d99a9e0e0e2ab14e6b8df265fc0b3", Utils.convertBytesToHex(sha2.computeHash(
                     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-256 hashing, with especially large data. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void test4_224() {
        StringBuilder testString = new StringBuilder(1000000);
        for (int i = 0; i < 1000000; ++i) {
            testString.append('a');
        }
        
        assertEquals("20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67", Utils.convertBytesToHex(sha2.computeHash(
                     testString.toString().getBytes(StandardCharsets.UTF_8))));
    }
}
