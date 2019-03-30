
package com.github.hisahi.tiralabradesaes.hash;

import com.github.hisahi.tiralabradesaes.Utils;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class HashSHA2_256Test {
    
    private HashSHA2_256 sha2;
    
    @Before
    public void setUp() {
        sha2 = new HashSHA2_256();
    }

    /**
     * Test case for SHA2-256 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test0_256() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Utils.convertBytesToHex(sha2.computeHash(
                     "".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA1 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test1_256() {
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Utils.convertBytesToHex(sha2.computeHash(
                     "abc".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA1 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test2_256() {
        assertEquals("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", Utils.convertBytesToHex(sha2.computeHash(
                     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA1 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test3_256() {
        assertEquals("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1", Utils.convertBytesToHex(sha2.computeHash(
                     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA1 hashing, with especially large data. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void test4_256() {
        StringBuilder testString = new StringBuilder(1000000);
        for (int i = 0; i < 1000000; ++i) {
            testString.append('a');
        }
        
        assertEquals("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", Utils.convertBytesToHex(sha2.computeHash(
                     testString.toString().getBytes(StandardCharsets.UTF_8))));
    }
}
