
package com.github.hisahi.tiralabradesaes.hash;

import com.github.hisahi.tiralabradesaes.Utils;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class HashSHA2_384Test {
    
    private HashSHA2_384 sha2;
    
    @Before
    public void setUp() {
        sha2 = new HashSHA2_384();
    }

    /**
     * Test case for SHA2-512 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test0_384() {
        assertEquals("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b", Utils.convertBytesToHex(sha2.computeHash(
                     "".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-512 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test1_384() {
        assertEquals("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7", Utils.convertBytesToHex(sha2.computeHash(
                     "abc".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-512 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test2_384() {
        assertEquals("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b", Utils.convertBytesToHex(sha2.computeHash(
                     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-512 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test3_384() {
        assertEquals("09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039", Utils.convertBytesToHex(sha2.computeHash(
                     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-512 hashing, with especially large data. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void test4_384() {
        StringBuilder testString = new StringBuilder(1000000);
        for (int i = 0; i < 1000000; ++i) {
            testString.append('a');
        }
        
        assertEquals("9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985", Utils.convertBytesToHex(sha2.computeHash(
                     testString.toString().getBytes(StandardCharsets.UTF_8))));
    }
}
