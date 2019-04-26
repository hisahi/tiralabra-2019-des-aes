
package com.github.hisahi.tiralabradesaes.keyderiv; 

import com.github.hisahi.tiralabradesaes.Utils;
import java.util.Arrays;

/**
 * Implements PBKDF2 (Password-Based Key Derivation Function 2), a key
 * derivation function that takes in a passphrase and salt and turns
 * them into a cryptographic key.
 */
public class KeyDerivPBKDF2 implements IKeyDerivation {
    
    private final HMACFunction hmac;
    private long cost;
    
    /**
     * Creates a KeyDerivPBKDF2 instance from the given HMAC function 
     * and a cost value. The cost value controls the number of iterations
     * and increases the amount of time it takes to derive a key.
     * 
     * @param prf The HMAC function to be used to derive the key.
     * @param c The cost value; higher values take longer but have better
     *          security against brute-force attacks.
     */
    public KeyDerivPBKDF2(HMACFunction prf, long c) {
        hmac = prf;
        setCost(c);
    }
    
    @Override
    public long getCost() {
        return cost;
    }
    
    @Override
    public void setCost(long c) {
        if (c <= 0) {
            throw new IllegalArgumentException("cost must be positive");
        }
        cost = c;
    }
    
    @Override
    public void calibrateTime(int ms, int keySize) {
        if (ms <= 0 || keySize <= 0) {
            throw new IllegalArgumentException("ms, keySize must be positive");
        }
        
        long startValue = System.currentTimeMillis(), 
                endValue = System.currentTimeMillis();
        byte[] key = new byte[keySize];
        byte[] salt = new byte[hmac.getBlockSize()];
                
        cost = 0;
        
        while ((endValue - startValue) < (ms + 1) / 2) {
            if (cost < 2) {
                cost += 1;
            } else {
                cost = 3 * cost / 2;
            }
            
            startValue = System.currentTimeMillis();
            deriveKey(key, key, salt);
            endValue = System.currentTimeMillis();
        }
        
        long trialTime = 0;
        
        for (int i = 0; i < 3; ++i) {
            startValue = System.currentTimeMillis();
            deriveKey(key, key, salt);
            trialTime += System.currentTimeMillis() - startValue;
        }
        
        cost = (long) cost * ms * 3 / trialTime;
    }

    @Override
    public void deriveKey(byte[] key, byte[] password, byte[] salt) {
        byte[] fullSalt = new byte[salt.length + 4];
        byte[] u;
        byte[] v = new byte[Math.max(fullSalt.length, hmac.getHashLength())];
        Utils.arraycopy(salt, 0, fullSalt, 0, salt.length);
        
        for (int i = 0; i < key.length; i += hmac.getHashLength()) {
            // increment fullSalt
            for (int j = fullSalt.length - 1; j >= salt.length; --j) {
                // increment last byte, but keep going if wraparound (ripple)
                // the last uint32 should not wrap into salt itself
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
            Utils.arraycopy(v, 0, key, i, Math.min(i + hmac.getHashLength(), 
                    key.length) - i);
        }
        hmac.reset();
    }

}
