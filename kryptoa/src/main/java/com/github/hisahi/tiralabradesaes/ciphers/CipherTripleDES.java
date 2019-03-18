
package com.github.hisahi.tiralabradesaes.ciphers; 

import com.github.hisahi.tiralabradesaes.Utils;
import java.util.Arrays;

/**
 * Implements 3DES-3TDEA, with three DES encryptions with three separate keys.
 * Each key is 64 bits (56 bits of security), which means 3DES expects
 * 192-bit (with 168 bits of security) keys.
 */
public class CipherTripleDES implements IBlockCipher {

    private boolean init;
    private boolean encrypting;
    private CipherDES des1;
    private CipherDES des2;
    private CipherDES des3;
    
    public CipherTripleDES() {
        init = false;
        encrypting = false;
        des1 = new CipherDES();
        des2 = new CipherDES();
        des3 = new CipherDES();
    }
    
    @Override
    public int getBlockSizeInBytes() {
        return 8;
    }
    
    @Override
    public boolean isValidKeySize(int bytes) {
        return bytes == 24;
    }

    @Override
    public void initEncrypt(byte[] key) {
        if (init) {
            throw new IllegalStateException("already init");
        }
        if (key.length != 24) {
            throw new IllegalArgumentException("key must be 192-bit, 24 bytes");
        }
        
        init = true;
        encrypting = true;
        
        // split into three keys
        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);
        
        // initialize DES with subkeys
        des1.initEncrypt(key1);
        des2.initDecrypt(key2);
        des3.initEncrypt(key3);
        
        Utils.destroyArray(key1);
        Utils.destroyArray(key2);
        Utils.destroyArray(key3);
    }

    @Override
    public void initDecrypt(byte[] key) {
        if (init) {
            throw new IllegalStateException("already init");
        }
        if (key.length != 24) {
            throw new IllegalArgumentException("key must be 192-bit, 24 bytes");
        }
        
        init = true;
        encrypting = false;
        
        // split into three keys
        byte[] key1 = Arrays.copyOfRange(key, 0, 8);
        byte[] key2 = Arrays.copyOfRange(key, 8, 16);
        byte[] key3 = Arrays.copyOfRange(key, 16, 24);
        
        // initialize DES with subkeys
        des1.initDecrypt(key1);
        des2.initEncrypt(key2);
        des3.initDecrypt(key3);
        
        Utils.destroyArray(key1);
        Utils.destroyArray(key2);
        Utils.destroyArray(key3);
    }

    @Override
    public byte[] process(byte[] block) {
        if (encrypting)
            return des3.process(des2.process(des1.process(block)));
        else
            return des1.process(des2.process(des3.process(block)));
    }

    @Override
    public void finish() {
        if (!init) {
            throw new IllegalStateException("already finished");
        }
        
        des1.finish();
        des2.finish();
        des3.finish();
        
        init = false;
    }

}
