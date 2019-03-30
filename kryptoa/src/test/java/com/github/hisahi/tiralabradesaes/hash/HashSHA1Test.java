
package com.github.hisahi.tiralabradesaes.hash;

import com.github.hisahi.tiralabradesaes.Utils;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class HashSHA1Test {
    
    private HashSHA1 sha1;
    
    @Before
    public void setUp() {
        sha1 = new HashSHA1();
    }

    /**
     * Test case for SHA1 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test0() {
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", Utils.convertBytesToHex(sha1.computeHash(
                     "".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA1 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test1() {
        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", Utils.convertBytesToHex(sha1.computeHash(
                     "abc".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA1 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test2() {
        assertEquals("84983e441c3bd26ebaae4aa1f95129e5e54670f1", Utils.convertBytesToHex(sha1.computeHash(
                     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA1 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test3() {
        assertEquals("a49b2446a02c645bf419f995b67091253a04a259", Utils.convertBytesToHex(sha1.computeHash(
                     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA1 hashing, with especially large data. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void test4() {
        StringBuilder testString = new StringBuilder(1000000);
        for (int i = 0; i < 1000000; ++i) {
            testString.append('a');
        }
        
        assertEquals("34aa973cd4c4daa4f61eeb2bdbad27316534016f", Utils.convertBytesToHex(sha1.computeHash(
                     testString.toString().getBytes(StandardCharsets.UTF_8))));
    }
}
