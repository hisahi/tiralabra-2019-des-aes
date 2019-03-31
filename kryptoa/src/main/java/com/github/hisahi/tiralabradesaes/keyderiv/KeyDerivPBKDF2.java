
package com.github.hisahi.tiralabradesaes.keyderiv; 

import java.util.Arrays;

/**
 * Implements PBKDF2 (Password-Based Key Derivation Function 2), a key
 * derivation function that takes in a passphrase and salt and turns
 * them into a cryptographic key.
 */
public class KeyDerivPBKDF2 implements IKeyDerivation {
    
    private HMACFunction hmac;
    private int cost;
    
    /**
     * Creates a KeyDerivPBKDF2 instance from the given HMAC function 
     * and a cost value. The cost value controls the number of iterations
     * and increases the amount of time it takes to derive a key.
     * 
     * @param prf The HMAC function to be used to derive the key.
     * @param c The cost value; higher values take longer but have better
     *          security against brute-force attacks.
     */
    public KeyDerivPBKDF2(HMACFunction prf, int c) {
        hmac = prf;
        setCost(c);
    }
    
    /**
     * Sets the cost used by PBKDF2.
     * 
     * @param c The cost value; higher values take longer but have better
     *          security against brute-force attacks.
     */
    public void setCost(int c) {
        if (c <= 0) {
            throw new IllegalArgumentException("cost must be at least 1");
        }
        cost = c;
    }

    @Override
    public void deriveKey(byte[] key, byte[] password, byte[] salt) {
        byte[] fullSalt = new byte[salt.length + 4];
        byte[] u;
        byte[] v = new byte[fullSalt.length];
        System.arraycopy(salt, 0, fullSalt, 0, salt.length);
        
        for (int i = 0; i < key.length; i += hmac.getHashLength()) {
            // increment fullSalt
            for (int j = fullSalt.length - 1; j >= 0; --j) {
                // increment last byte, but if it wraps around, keep going (ripple)
                if (++fullSalt[j] != 0) {
                    break;
                }
            }
            // initial salt is the salt given
            u = Arrays.copyOf(fullSalt, fullSalt.length);
            
            for (int j = 0; j < cost; ++j) {
                u = hmac.computeHmac(password, u);
                for (int k = 0; k < u.length; ++k) {
                    v[k] ^= u[k];
                }
            }
            
            // copy HMAC to key, truncate if necessary
            System.arraycopy(v, 0, key, i, Math.min(i + hmac.getHashLength(), key.length) - i);
        }
        hmac.reset();
    }

}
