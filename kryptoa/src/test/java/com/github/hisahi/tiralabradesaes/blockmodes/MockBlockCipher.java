
package com.github.hisahi.tiralabradesaes.blockmodes; 
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;

/**
 * A mock IBlockCipher for testing IBlockMode implementations.
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
