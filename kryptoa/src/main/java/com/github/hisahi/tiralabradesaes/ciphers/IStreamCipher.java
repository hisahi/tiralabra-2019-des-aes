
package com.github.hisahi.tiralabradesaes.ciphers;

/**
 * Interface for symmetric stream ciphers.
 */
public interface IStreamCipher {
    
    /**
     * Checks whether the given key size is valid.
     * 
     * @param bytes The proposed size of the key in bytes,
     * @return Whether a key with the zize matching the given number of bytes
     *         is valid.
     */
    public boolean isValidKeySize(int bytes);
    
    /**
     * Initializes the given stream cipher. To be called
     * before either process() or finish(). Calling init()
     * after initialization and before finishing is invalid.
     * 
     * @param key The key to initialize with.
     * @param nonce A nonce value, designed to be only used once
     *              per initialization.
     */
    public void init(byte[] key, byte[] nonce);
    
    /**
     * Encrypts or decrypts any amount of data given. Note that the
     * given byte array might be modified by the implementation.
     * 
     * @param block The data to encrypt or decrypt.
     * @return The encrypted or decrypted data.
     */
    public byte[] process(byte[] block);
    
    /**
     * Finish processing. The cipher should be able to be initialized 
     * again after finish() has been called.
     */
    public void finish();
    
}
