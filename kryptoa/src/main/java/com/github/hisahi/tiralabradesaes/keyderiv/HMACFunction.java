
package com.github.hisahi.tiralabradesaes.keyderiv; 

import com.github.hisahi.tiralabradesaes.hash.IHashFunction;
import java.util.Arrays;

/**
 * Implements a HMAC (hash-based message authentication code) function, 
 * acting as a wrapper for an underlying hash function.
 */
public class HMACFunction {
    
    private IHashFunction h;
    private byte[] rkey;
    private byte[] opad;
    private byte[] ipad;
    
    /**
     * Initializes a HMACFunction for the given hash function.
     * 
     * @param hash The hash function to be used to compute the HMAC.
     */
    public HMACFunction(IHashFunction hash) {
        h = hash;
        rkey = new byte[0];
        opad = new byte[0];
        ipad = new byte[0];
    }
    
    /**
     * The length of the resulting HMAC in bytes.
     * 
     * @return The result of the HMAC in bytes; same as the length of the hash
     *         of the underlying hash function.
     */
    public int getHashLength() {
        return h.getHashLength();   
    }
    
    /**
     * Computes the HMAC for the given key and message.
     * 
     * @param key The key used to compute the HMAC.
     * @param message The message used to compute the HMAC.
     * @return The resulting HMAC.
     */
    public byte[] computeHmac(byte[] key, byte[] message) {
        if (key.length > h.getBlockSize()) {
            // if too long, compute hash
            rkey = h.computeHash(key);
        } else {
            rkey = key;
        }
        
        if (key.length < h.getBlockSize()) {
            // pad
            rkey = Arrays.copyOf(rkey, h.getBlockSize());
        }
        
        int ol = rkey.length + h.getHashLength();
        int il = rkey.length + message.length;
        byte[] hash;
        
        if (ipad.length != il) {
            ipad = Arrays.copyOf(ipad, il);
        }
        if (opad.length != ol) {
            opad = Arrays.copyOf(ipad, ol);
        }
        
        for (int i = 0; i < rkey.length; ++i) {
            opad[i] = (byte) (rkey[i] ^ 0x5c);
            ipad[i] = (byte) (rkey[i] ^ 0x36);
        }
        
        System.arraycopy(message, 0, ipad, rkey.length, message.length);
        hash = h.computeHash(ipad);
        System.arraycopy(hash, 0, opad, rkey.length, hash.length);
        return h.computeHash(opad);
    }
    
    /**
     * Resets internal variables, recommended to be called after no more
     * HMACs need to be computed within a given function to improve security.
     */
    public void reset() {
        h.reset();
        Arrays.fill(rkey, (byte) 0);
        Arrays.fill(opad, (byte) 0);
        Arrays.fill(ipad, (byte) 0);
    }
    
}