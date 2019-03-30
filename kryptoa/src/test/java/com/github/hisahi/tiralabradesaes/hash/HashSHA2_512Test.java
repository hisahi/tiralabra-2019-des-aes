
package com.github.hisahi.tiralabradesaes.hash;

import com.github.hisahi.tiralabradesaes.Utils;
import java.nio.charset.StandardCharsets;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class HashSHA2_512Test {
    
    private HashSHA2_512 sha2;
    
    @Before
    public void setUp() {
        sha2 = new HashSHA2_512();
    }

    /**
     * Test case for SHA2-512 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test0_512() {
        assertEquals("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e", Utils.convertBytesToHex(sha2.computeHash(
                     "".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-512 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test1_512() {
        assertEquals("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", Utils.convertBytesToHex(sha2.computeHash(
                     "abc".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-512 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test2_512() {
        assertEquals("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445", Utils.convertBytesToHex(sha2.computeHash(
                     "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-512 hashing. The result has been tested against an
     * implementation known to work correctly.
     */
    @Test
    public void test3_512() {
        assertEquals("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909", Utils.convertBytesToHex(sha2.computeHash(
                     "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".getBytes(StandardCharsets.UTF_8))));
    }

    /**
     * Test case for SHA2-512 hashing, with especially large data. The result has
     * been tested against an implementation known to work correctly.
     */
    @Test
    public void test4_512() {
        StringBuilder testString = new StringBuilder(1000000);
        for (int i = 0; i < 1000000; ++i) {
            testString.append('a');
        }
        
        assertEquals("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b", Utils.convertBytesToHex(sha2.computeHash(
                     testString.toString().getBytes(StandardCharsets.UTF_8))));
    }
}
