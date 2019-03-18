
package com.github.hisahi.tiralabradesaes.ciphers; 

public class CipherAES implements IBlockCipher {

    @Override
    public int getBlockSizeInBytes() {
        return 16;
    }
    
    @Override
    public boolean isValidKeySize(int bytes) {
        return bytes == 16 || bytes == 24 || bytes == 32;
    }

    @Override
    public void initEncrypt(byte[] key) {
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public void initDecrypt(byte[] key) {
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public byte[] process(byte[] block) {
        throw new UnsupportedOperationException("TODO");
    }

    @Override
    public void finish() {
        throw new UnsupportedOperationException("TODO");
    }

}
