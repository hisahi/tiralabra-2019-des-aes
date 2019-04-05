
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
    
    /**
     * Gets the current cost of the key-derivation function. The value
     * should be a positive number, or 0 if the cost value is irrelevant
     * for this key derivation function.
     * 
     * @return The current cost value.
     */
    public long getCost();
    
    /**
     * Sets the cost used by this key derivation function.
     * 
     * @param c The cost value; higher values take longer but have better
     *          security against brute-force attacks.
     */
    public void setCost(long c);
    
    /**
     * Calibrates the given key derivation function to take approximately
     * ms milliseconds for every generated key assuming a salt size equal to
     * the block size of the underlying hash function and a key size equal to
     * the given parameter. The cost of the key derivation is adjusted 
     * accordingly.
     * 
     * @param ms The milliseconds to approximately take for every key.
     * @param keySize The size of the key to calibrate for.
     */
    public void calibrateTime(int ms, int keySize);
}
