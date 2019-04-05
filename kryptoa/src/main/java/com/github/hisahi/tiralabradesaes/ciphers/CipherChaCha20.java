
package com.github.hisahi.tiralabradesaes.ciphers; 

import com.github.hisahi.tiralabradesaes.Utils;

/**
 * Implements the ChaCha20 stream cipher.
 */
public class CipherChaCha20 implements IStreamCipher {
    
    private boolean initialized;
    private int[] state;
    private int[] tmp;
    private int cycle;

    @Override
    public boolean isValidKeySize(int bytes) {
        return bytes == 32;
    }

    @Override
    public void init(byte[] key, byte[] nonce) {
        if (initialized) {
            throw new IllegalStateException("already initialized");
        }
        if (key.length != 32) {
            throw new IllegalArgumentException("key must be 32B / 256b");
        }
        if (nonce.length != 8) {
            throw new IllegalArgumentException("nonce must be 8B / 64b");
        }
        
        int j = 0;

        state = new int[16];
        tmp = new int[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        cycle = 64;
        
        for (int i = 4; i < 12; ++i) {
            state[i] = ((key[j + 3] & 0xFF) << 24) 
                     | ((key[j + 2] & 0xFF) << 16) 
                     | ((key[j + 1] & 0xFF) <<  8)
                     | ((key[j    ] & 0xFF)      );
            j += 4;
        }
        
        // this is weird because of endianness switch
        state[14] = ((nonce[3] & 0xFF) << 24) | ((nonce[2] & 0xFF) << 16) 
                  | ((nonce[1] & 0xFF) <<  8) | ((nonce[0] & 0xFF)      );
        state[15] = ((nonce[7] & 0xFF) << 24) | ((nonce[6] & 0xFF) << 16) 
                  | ((nonce[5] & 0xFF) <<  8) | ((nonce[4] & 0xFF)      );
        
        initialized = true;
    }
    
    private void quarterRound(int a, int b, int c, int d) {
        tmp[a] += tmp[b]; tmp[d] ^= tmp[a];
        tmp[d] = (tmp[d] <<  16) | (tmp[d] >>> 16);
        tmp[c] += tmp[d]; tmp[b] ^= tmp[c];
        tmp[b] = (tmp[b] <<  12) | (tmp[b] >>> 20);
        tmp[a] += tmp[b]; tmp[d] ^= tmp[a];
        tmp[d] = (tmp[d] <<   8) | (tmp[d] >>> 24);
        tmp[c] += tmp[d]; tmp[b] ^= tmp[c];
        tmp[b] = (tmp[b] <<   7) | (tmp[b] >>> 25);
    }
    
    private void fullBlock() {
        for (int i = 0; i < 16; ++i) {
            tmp[i] = state[i];
        }
        
        for (int i = 0; i < 10; ++i) {
            // Odd
            quarterRound( 0,  4,  8, 12);
            quarterRound( 1,  5,  9, 13);
            quarterRound( 2,  6, 10, 14);   
            quarterRound( 3,  7, 11, 15);
            // Even
            quarterRound( 0,  5, 10, 15);
            quarterRound( 1,  6, 11, 12);   
            quarterRound( 2,  7,  8, 13);
            quarterRound( 3,  4,  9, 14);
        }
        
        for (int i = 0; i < 16; ++i) {
            tmp[i] += state[i];
        }
        
        // increment counter
        if (++state[12] != 0) return;
        if (++state[13] != 0) return;
        if (++state[14] != 0) return;
            ++state[15];
    }

    @Override
    public byte[] process(byte[] block) {
        if (!initialized) {
            throw new IllegalStateException("not initialized");
        }
        
        for (int i = 0; i < block.length; ++i) {
            if (cycle >= 64) {
                fullBlock();
                cycle = 0;
            }
            
            block[i] ^= 0xFF & (tmp[cycle >>> 2] >>> ((cycle & 3) << 3));
            ++cycle;
        }
        
        return block;
    }

    @Override
    public void finish() {
        if (!initialized) {
            throw new IllegalStateException("already finished");
        }
        
        Utils.destroyArray(tmp);
        Utils.destroyArray(state);
        initialized = false;
    }

}
