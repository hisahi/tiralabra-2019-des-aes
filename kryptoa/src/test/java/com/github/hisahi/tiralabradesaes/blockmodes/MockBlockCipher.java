
package com.github.hisahi.tiralabradesaes.blockmodes; 
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;

public class MockBlockCipher implements IBlockCipher {

    @Override
    public int getBlockSizeInBytes() {
        return 8;
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
