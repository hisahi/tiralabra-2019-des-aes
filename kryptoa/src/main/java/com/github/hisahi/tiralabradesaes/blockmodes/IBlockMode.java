
package com.github.hisahi.tiralabradesaes.blockmodes;

/**
 * Interface for block cipher modes of operation.
 */
public interface IBlockMode {
    /**
     * Checks whether the given IV size is valid.
     * 
     * @param bytes The proposed size of the IV in bytes,
     * @return Whether an IV with the size matching the given number of bytes
     *         is valid.
     */
    public boolean isValidIVSize(int bytes);
    
    /**
     * Initializes the block cipher mode of operation for encrypting blocks.
     * Guaranteed to be called before either process() or finish().
     * Calling again is invalid before finish() is called. This will also
     * initialize the underlying block cipher with the given key.
     * 
     * @param key The key to initialize the cipher with. May not be null.
     * @param iv The IV or initialization vector. May only be null when the
     * block cipher mode of operation does not accept IVs.
     */
    public void initEncrypt(byte[] key, byte[] iv);
    
    /**
     * Initializes the block cipher mode of operation for decrypting blocks.
     * Guaranteed to be called before either process() or finish().
     * Calling again is invalid before finish() is called. This will also
     * initialize the underlying block cipher with the given key.
     * 
     * @param key The key to initialize the cipher with. May not be null.
     * @param iv The IV or initialization vector. May only be null when the
     * block cipher mode of operation does not accept IVs.
     */
    public void initDecrypt(byte[] key, byte[] iv);
    
    /**
     * Processes a single block of plaintext. The intended workflow is:<ol>
     * <li>init block mode with key and IV; initializes block cipher</li>
     * <li>call block mode process to encrypt or decrypt a plaintext block</li>
     * <li>finish block mode, which will also finish the cipher</li>
     * </ol>
     *  
     * Note that the given byte array might be modified by the implementation.
     * 
     * @param data The block of plaintext data to process.
     * @return The encrypted or decrypted block of data.
     */
    public byte[] process(byte[] data);
    
    /**
     * Finishes the block mode of operation, after which it has to be
     * initialized again for it to work.
     */
    public void finish();
}
