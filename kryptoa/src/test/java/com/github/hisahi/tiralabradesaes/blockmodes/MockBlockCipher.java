
package com.github.hisahi.tiralabradesaes.blockmodes; 
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;

/**
 * A mock IBlockCipher for testing IBlockMode implementations.
 * It uses 8-byte 64-bit blocks, but only in principle, as any data given
 * will not be modified in any way.
 */
public class MockBlockCipher implements IBlockCipher {

    @Override
    public int getBlockSizeInBytes() {
        return 8;
    }

    @Override
    public boolean isValidKeySize(int bytes) {
        return true;
    }

    @Override
    public void initEncrypt(byte[] key) {
    }

    @Override
    public void initDecrypt(byte[] key) {
    }

    @Override
    public byte[] process(byte[] block) {
        return block;
    }

    @Override
    public void finish() {
    }

}
