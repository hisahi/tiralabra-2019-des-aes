
package com.github.hisahi.tiralabradesaes.keyderiv; 

/**
 * Describes a key derivation function that creates a key from a passphrase
 * and salt.
 */
public interface IKeyDerivation {
    /* Extra parameters can be given via constructor */
    
    /**
     * Derives a key from the given password and salt and
     * places it into the given byte array.
     * 
     * @param key The output byte array where the derived key will be stored.
     * @param password The passphrase to use when deriving the key.
     * @param salt The salt to use when deriving the key.
     */
    public void deriveKey(byte[] key, byte[] password, byte[] salt);
}
