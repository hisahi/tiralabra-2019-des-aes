
package com.github.hisahi.tiralabradesaes.ciphers;

/**
 * Interface for block ciphers.
 */
public interface IBlockCipher {
    
    /**
     * Gets the block size of the cipher in bytes.
     * 
     * @return The size of the cipher block in bytes.
     */
    public int getBlockSizeInBytes();
    
    /**
     * Checks whether the given key size is valid.
     * 
     * @param bytes The proposed size of the key in bytes,
     * @return Whether a key with the zize matching the given number of bytes
     *         is valid.
     */
    public boolean isValidKeySize(int bytes);
    
    /**
     * Initializes the block cipher for encryption. To be called
     * before either process() or finish(). Calling initEncrypt()
     * after initialization and before finishing is invalid.
     * 
     * @param key The key represented as a byte array. May not be null.
     */
    public void initEncrypt(byte[] key);
    
    /**
     * Initializes the block cipher for decryption. To be called
     * before either process() or finish(). Calling initDecrypt()
     * after initialization and before finishing is invalid.
     * 
     * @param key The key represented as a byte array. May not be null.
     */
    public void initDecrypt(byte[] key);
    
    /**
     * Encrypts or decrypts a single block of data. Note that the
     * given byte array might be modified by the implementation.
     * 
     * @param block The block of data to encrypt or decrypt.
     * @return The encrypted or decrypted block of data.
     */
    public byte[] process(byte[] block);
    
    /**
     * Finish encryption or decryption. The cipher should be able
     * to be initialized again after finish() has been called.
     */
    public void finish();
}
