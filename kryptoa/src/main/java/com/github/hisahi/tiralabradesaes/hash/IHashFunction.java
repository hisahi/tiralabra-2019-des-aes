
package com.github.hisahi.tiralabradesaes.hash; 

/**
 * Represents a hash function.
 */
public interface IHashFunction {

    /**
     * Gets the size of the hash computed by the hash function.
     * 
     * @return The size of the hash in bytes.
     */
    public int getHashLength();

    /**
     * Gets the block size used by the hash function.
     * 
     * @return The size of the block in bytes.
     */
    public int getBlockSize();
    
    /**
     * Computes a hash of the given byte array.
     * 
     * @param data The data to hash.
     * @return The resulting hash as a byte array.
     */
    public byte[] computeHash(byte[] data);
    
    /**
     * Resets internal variables. Recommended to be called when
     * no more hashes need to be computed in a given function.
     */
    public void reset();
    
}
