
package com.github.hisahi.tiralabradesaes.ciphers; 

import com.github.hisahi.tiralabradesaes.Utils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class CipherChaCha20UnitTest {
    private CipherChaCha20 c;
    
    @Before
    public void setUp() {
        c = new CipherChaCha20();
    }
    
    @After
    public void tearDown() {
        try {
            c.finish();
        } catch (IllegalStateException ex) {}
    }
    
    /**
     * Simple test case. The result has been tested against an implementation 
     * known to work correctly.
     */
    @Test
    public void testChaCha20_1() {
        c.init(Utils.convertHexToBytes("00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"), 
               Utils.convertHexToBytes("0000000000000000"));
        byte[] res = c.process(      Utils.convertHexToBytes(
                                       "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"));
        assertEquals(                  "76b8e0ada0f13d90405d6ae55386bd28"
                                     + "bdd219b8a08ded1aa836efcc8b770dc7"
                                     + "da41597c5157488d7724e03fb8d84a37"
                                     + "6a43b8f41518a11cc387b669b2ee6586"
                                     , Utils.convertBytesToHex(res));
    }
    
    /**
     * Simple test case. The result has been tested against an implementation 
     * known to work correctly.
     */
    @Test
    public void testChaCha20_2() {
        c.init(Utils.convertHexToBytes("000102030405060708090a0b0c0d0e0f"
                                     + "101112131415161718191a1b1c1d1e1f"), 
               Utils.convertHexToBytes("0001020304050607"));
        byte[] res = c.process(      Utils.convertHexToBytes(
                                       "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"
                                     + "00000000000000000000000000000000"));
        assertEquals(                  "f798a189f195e66982105ffb640bb775"
                                     + "7f579da31602fc93ec01ac56f85ac3c1"
                                     + "34a4547b733b46413042c94400491769"
                                     + "05d3be59ea1c53f15916155c2be8241a"
                                     + "38008b9a26bc35941e2444177c8ade66"
                                     + "89de95264986d95889fb60e84629c9bd"
                                     + "9a5acb1cc118be563eb9b3a4a472f82e"
                                     + "09a7e778492b562ef7130e88dfe031c7"
                                     + "9db9d4f7c7a899151b9a475032b63fc3"
                                     + "85245fe054e3dd5a97a5f576fe064025"
                                     + "d3ce042c566ab2c507b138db853e3d69"
                                     + "59660996546cc9c4a6eafdc777c040d7"
                                     , Utils.convertBytesToHex(res));
    }
    /**
     * The cipher should not accept keys of wrong size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void notAllowingKeyOfWrongSize() {
        c.init(Utils.convertHexToBytes("01"), 
               Utils.convertHexToBytes("0123456789abcdef"));
    }

    /**
     * The cipher should not accept nonces of wrong size.
     */
    @Test(expected = IllegalArgumentException.class)
    public void notAllowingNonceOfWrongSize() {
        c.init(Utils.convertHexToBytes("01010101010101010101010101010101"
                                     + "01010101010101010101010101010101"), 
               Utils.convertHexToBytes("01"));
    }

    /**
     * process() should raise an exception when called before the cipher
     * is initialized.
     */
    @Test(expected = IllegalStateException.class)
    public void notProcessBeforeInit() {
        c.process(Utils.convertHexToBytes("01"));
    }

    /**
     * Two consecutive initialization calls without an intermediate finish()
     * should fail.
     */
    @Test(expected = IllegalStateException.class)
    public void notDoubleInit() {
        c.init(Utils.convertHexToBytes("01010101010101010101010101010101"
                                     + "01010101010101010101010101010101"), 
               Utils.convertHexToBytes("0123456789abcdef"));
        c.init(Utils.convertHexToBytes("01010101010101010101010101010101"
                                     + "01010101010101010101010101010101"),
               Utils.convertHexToBytes("0123456789abcdef"));
    }

    /**
     * Two consecutive finish() calls without an intermediate initialization
     * should fail.
     */
    @Test(expected = IllegalStateException.class)
    public void notDoubleFinish() {
        c.init(Utils.convertHexToBytes("01010101010101010101010101010101"
                                     + "01010101010101010101010101010101"), 
               Utils.convertHexToBytes("0123456789abcdef"));
        c.finish();
        c.finish();
    }

    /**
     * process() should raise an exception when called between a call
     * to finish() and a new initialization.
     */
    @Test(expected = IllegalStateException.class)
    public void notProcessAfterFinish() {
        c.init(Utils.convertHexToBytes("01010101010101010101010101010101"
                                     + "01010101010101010101010101010101"), 
               Utils.convertHexToBytes("0123456789abcdef"));
        c.finish();
        c.process(Utils.convertHexToBytes("01"));
    }
}
