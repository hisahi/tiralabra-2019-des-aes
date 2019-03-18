
package com.github.hisahi.tiralabradesaes.blockmodes;

/**
 * Interface for block cipher modes of operation.
 */
public interface IBlockMode {
    /**
     * Checks whether the given IV size is valid.
     * 
     * @return Whether an IV with the zize matching the given number of bytes
     *         is valid.
     */
    public boolean isValidIVSize(int bytes);
    
    /**
     * Initializes the block cipher mode of operation for encrypting blocks.
     * Guaranteed to be called before either process() or finish().
     * Calling again is invalid before finish() is called.
     * 
     * @param iv The IV or initialization vector. May only be null when the
     * block cipher mode of operation does not accept IVs.
     */
    public void initEncrypt(byte[] iv);
    
    /**
     * Initializes the block cipher mode of operation for decrypting blocks.
     * Guaranteed to be called before either process() or finish().
     * Calling again is invalid before finish() is called.
     * 
     * @param iv The IV or initialization vector. May only be null when the
     * block cipher mode of operation does not accept IVs.
     */
    public void initDecrypt(byte[] iv);
    
    /**
     * Processes a single block of plaintext. The intended workflow is:<ol>
     * <li>init block cipher with key</li>
     * <li>init block mode with IV and cipher</li>
     * <li>call block mode process to encrypt or decrypt a plaintext block</li>
     * <li>finish block cipher</li>
     * <li>finish block mode</li>
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
