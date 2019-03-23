
package com.github.hisahi.tiralabradesaes.ciphers; 

import com.github.hisahi.tiralabradesaes.Utils;
import java.util.Arrays;

/**
 * Implements AES with three possible key sizes: 128 bits, 
 * 192 bits and 256 bits.
 */
public class CipherAES implements IBlockCipher {
    // AES/Rijndael S-box
    /* private */ static final byte[] AES_S = new byte[] { 0x63, 0x7c, 0x77, 0x7b, (byte) 0xf2, 0x6b, 0x6f, (byte) 0xc5, 0x30, 0x01, 0x67, 0x2b, (byte) 0xfe, (byte) 0xd7, (byte) 0xab, 0x76, (byte) 0xca, (byte) 0x82, (byte) 0xc9, 0x7d, (byte) 0xfa, 0x59, 0x47, (byte) 0xf0, (byte) 0xad, (byte) 0xd4, (byte) 0xa2, (byte) 0xaf, (byte) 0x9c, (byte) 0xa4, 0x72, (byte) 0xc0, (byte) 0xb7, (byte) 0xfd, (byte) 0x93, 0x26, 0x36, 0x3f, (byte) 0xf7, (byte) 0xcc, 0x34, (byte) 0xa5, (byte) 0xe5, (byte) 0xf1, 0x71, (byte) 0xd8, 0x31, 0x15, 0x04, (byte) 0xc7, 0x23, (byte) 0xc3, 0x18, (byte) 0x96, 0x05, (byte) 0x9a, 0x07, 0x12, (byte) 0x80, (byte) 0xe2, (byte) 0xeb, 0x27, (byte) 0xb2, 0x75, 0x09, (byte) 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, (byte) 0xa0, 0x52, 0x3b, (byte) 0xd6, (byte) 0xb3, 0x29, (byte) 0xe3, 0x2f, (byte) 0x84, 0x53, (byte) 0xd1, 0x00, (byte) 0xed, 0x20, (byte) 0xfc, (byte) 0xb1, 0x5b, 0x6a, (byte) 0xcb, (byte) 0xbe, 0x39, 0x4a, 0x4c, 0x58, (byte) 0xcf, (byte) 0xd0, (byte) 0xef, (byte) 0xaa, (byte) 0xfb, 0x43, 0x4d, 0x33, (byte) 0x85, 0x45, (byte) 0xf9, 0x02, 0x7f, 0x50, 0x3c, (byte) 0x9f, (byte) 0xa8, 0x51, (byte) 0xa3, 0x40, (byte) 0x8f, (byte) 0x92, (byte) 0x9d, 0x38, (byte) 0xf5, (byte) 0xbc, (byte) 0xb6, (byte) 0xda, 0x21, 0x10, (byte) 0xff, (byte) 0xf3, (byte) 0xd2, (byte) 0xcd, 0x0c, 0x13, (byte) 0xec, 0x5f, (byte) 0x97, 0x44, 0x17, (byte) 0xc4, (byte) 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, (byte) 0x81, 0x4f, (byte) 0xdc, 0x22, 0x2a, (byte) 0x90, (byte) 0x88, 0x46, (byte) 0xee, (byte) 0xb8, 0x14, (byte) 0xde, 0x5e, 0x0b, (byte) 0xdb, (byte) 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, (byte) 0xc2, (byte) 0xd3, (byte) 0xac, 0x62, (byte) 0x91, (byte) 0x95, (byte) 0xe4, 0x79, (byte) 0xe7, (byte) 0xc8, 0x37, 0x6d, (byte) 0x8d, (byte) 0xd5, 0x4e, (byte) 0xa9, 0x6c, 0x56, (byte) 0xf4, (byte) 0xea, 0x65, 0x7a, (byte) 0xae, 0x08, (byte) 0xba, 0x78, 0x25, 0x2e, 0x1c, (byte) 0xa6, (byte) 0xb4, (byte) 0xc6, (byte) 0xe8, (byte) 0xdd, 0x74, 0x1f, 0x4b, (byte) 0xbd, (byte) 0x8b, (byte) 0x8a, 0x70, 0x3e, (byte) 0xb5, 0x66, 0x48, 0x03, (byte) 0xf6, 0x0e, 0x61, 0x35, 0x57, (byte) 0xb9, (byte) 0x86, (byte) 0xc1, 0x1d, (byte) 0x9e, (byte) 0xe1, (byte) 0xf8, (byte) 0x98, 0x11, 0x69, (byte) 0xd9, (byte) 0x8e, (byte) 0x94, (byte) 0x9b, 0x1e, (byte) 0x87, (byte) 0xe9, (byte) 0xce, 0x55, 0x28, (byte) 0xdf, (byte) 0x8c, (byte) 0xa1, (byte) 0x89, 0x0d, (byte) 0xbf, (byte) 0xe6, 0x42, 0x68, 0x41, (byte) 0x99, 0x2d, 0x0f, (byte) 0xb0, 0x54, (byte) 0xbb, 0x16 };
    // AES/Rijndael S-box inverse
    /* private */ static final byte[] AES_IS = new byte[] { 0x52, 0x09, 0x6a, (byte) 0xd5, 0x30, 0x36, (byte) 0xa5, 0x38, (byte) 0xbf, 0x40, (byte) 0xa3, (byte) 0x9e, (byte) 0x81, (byte) 0xf3, (byte) 0xd7, (byte) 0xfb, 0x7c, (byte) 0xe3, 0x39, (byte) 0x82, (byte) 0x9b, 0x2f, (byte) 0xff, (byte) 0x87, 0x34, (byte) 0x8e, 0x43, 0x44, (byte) 0xc4, (byte) 0xde, (byte) 0xe9, (byte) 0xcb, 0x54, 0x7b, (byte) 0x94, 0x32, (byte) 0xa6, (byte) 0xc2, 0x23, 0x3d, (byte) 0xee, 0x4c, (byte) 0x95, 0x0b, 0x42, (byte) 0xfa, (byte) 0xc3, 0x4e, 0x08, 0x2e, (byte) 0xa1, 0x66, 0x28, (byte) 0xd9, 0x24, (byte) 0xb2, 0x76, 0x5b, (byte) 0xa2, 0x49, 0x6d, (byte) 0x8b, (byte) 0xd1, 0x25, 0x72, (byte) 0xf8, (byte) 0xf6, 0x64, (byte) 0x86, 0x68, (byte) 0x98, 0x16, (byte) 0xd4, (byte) 0xa4, 0x5c, (byte) 0xcc, 0x5d, 0x65, (byte) 0xb6, (byte) 0x92, 0x6c, 0x70, 0x48, 0x50, (byte) 0xfd, (byte) 0xed, (byte) 0xb9, (byte) 0xda, 0x5e, 0x15, 0x46, 0x57, (byte) 0xa7, (byte) 0x8d, (byte) 0x9d, (byte) 0x84, (byte) 0x90, (byte) 0xd8, (byte) 0xab, 0x00, (byte) 0x8c, (byte) 0xbc, (byte) 0xd3, 0x0a, (byte) 0xf7, (byte) 0xe4, 0x58, 0x05, (byte) 0xb8, (byte) 0xb3, 0x45, 0x06, (byte) 0xd0, 0x2c, 0x1e, (byte) 0x8f, (byte) 0xca, 0x3f, 0x0f, 0x02, (byte) 0xc1, (byte) 0xaf, (byte) 0xbd, 0x03, 0x01, 0x13, (byte) 0x8a, 0x6b, 0x3a, (byte) 0x91, 0x11, 0x41, 0x4f, 0x67, (byte) 0xdc, (byte) 0xea, (byte) 0x97, (byte) 0xf2, (byte) 0xcf, (byte) 0xce, (byte) 0xf0, (byte) 0xb4, (byte) 0xe6, 0x73, (byte) 0x96, (byte) 0xac, 0x74, 0x22, (byte) 0xe7, (byte) 0xad, 0x35, (byte) 0x85, (byte) 0xe2, (byte) 0xf9, 0x37, (byte) 0xe8, 0x1c, 0x75, (byte) 0xdf, 0x6e, 0x47, (byte) 0xf1, 0x1a, 0x71, 0x1d, 0x29, (byte) 0xc5, (byte) 0x89, 0x6f, (byte) 0xb7, 0x62, 0x0e, (byte) 0xaa, 0x18, (byte) 0xbe, 0x1b, (byte) 0xfc, 0x56, 0x3e, 0x4b, (byte) 0xc6, (byte) 0xd2, 0x79, 0x20, (byte) 0x9a, (byte) 0xdb, (byte) 0xc0, (byte) 0xfe, 0x78, (byte) 0xcd, 0x5a, (byte) 0xf4, 0x1f, (byte) 0xdd, (byte) 0xa8, 0x33, (byte) 0x88, 0x07, (byte) 0xc7, 0x31, (byte) 0xb1, 0x12, 0x10, 0x59, 0x27, (byte) 0x80, (byte) 0xec, 0x5f, 0x60, 0x51, 0x7f, (byte) 0xa9, 0x19, (byte) 0xb5, 0x4a, 0x0d, 0x2d, (byte) 0xe5, 0x7a, (byte) 0x9f, (byte) 0x93, (byte) 0xc9, (byte) 0x9c, (byte) 0xef, (byte) 0xa0, (byte) 0xe0, 0x3b, 0x4d, (byte) 0xae, 0x2a, (byte) 0xf5, (byte) 0xb0, (byte) 0xc8, (byte) 0xeb, (byte) 0xbb, 0x3c, (byte) 0x83, 0x53, (byte) 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, (byte) 0xba, 0x77, (byte) 0xd6, 0x26, (byte) 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
    // AES/Rijndael key schedule rcon_i
    /* private */ static final int[] AES_RCON = new int[] { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, (int) 0x80000000, 0x1B000000, 0x36000000 };
    
    /* private */ boolean init;
    /* private */ boolean encrypting;
    /* private */ int rounds;
    // temporary variables
    /* private */ int t0, t1, t2, t3;
    /* private */ int a0, a1, a2, a3;
    /* private */ int b0, b1, b2, b3, bm;
    
    // key schedule, R+1 128b keys
    /* private */ int[] key0;
    /* private */ int[] key1;
    /* private */ int[] key2;
    /* private */ int[] key3;

    @Override
    public int getBlockSizeInBytes() {
        return 16;
    }
    
    @Override
    public boolean isValidKeySize(int bytes) {
        return bytes == 16 || bytes == 24 || bytes == 32;
    }
    
    /* private */ void initBase(byte[] key, boolean willEncrypt) {
        if (init) {
            throw new IllegalStateException("already init");
        }
        if (!isValidKeySize(key.length)) {
            throw new IllegalArgumentException("invalid key size; must be 128b, 192b or 256b");
        }
        
        // number of rounds depends on key size
        switch (key.length) {
            case 16:
                rounds = 10;
                break;
            case 24:
                rounds = 12;
                break;
            case 32:
                rounds = 14;
                break;
        }
        
        // key schedule
        key0 = new int[rounds + 1];
        key1 = new int[rounds + 1];
        key2 = new int[rounds + 1];
        key3 = new int[rounds + 1];
        
        // kN = length of key in 32b words
        int kN = key.length / 4;
        int[] k32 = new int[kN];
        int[][] keyOut = new int[][] { key0, key1, key2, key3 };
        
        // split key to 32b keys
        for (int i = 0; i < key.length; i += 4) {
            k32[i >> 2] = ((key[i    ] & 0xFF) << 24) 
                        | ((key[i + 1] & 0xFF) << 16) 
                        | ((key[i + 2] & 0xFF) <<  8) 
                        |  (key[i + 3] & 0xFF);
        }
        
        int t; // tmp
        for (int i = 0; i < 4 * (rounds + 1); ++i) {
            // branches are fine here because the only property of the key
            // the branch taken depends on is the size of the key, not a very
            // useful information for side-channel attacks... wait why do I 
            // think this is enough to make this all immune to them anyway?
            
            if (i < kN) {
                keyOut[i & 3][i >> 2] = k32[i];
            } else if ((i % kN) == 0) {
                t = keyOut[(i - 1) & 3][(i - 1) >> 2]; 
                // AES RotWord
                t = (t << 8) | (t >>> 24);
                // AES SubWord
                t =   ((AES_S[(t >>> 24) & 0xFF]) & 0xFF) << 24
                    | ((AES_S[(t >>> 16) & 0xFF]) & 0xFF) << 16
                    | ((AES_S[(t >>>  8) & 0xFF]) & 0xFF) <<  8
                    | ((AES_S[(t       ) & 0xFF]) & 0xFF);
                t ^= AES_RCON[(i / kN) - 1];
                keyOut[i & 3][i >> 2] = keyOut[(i - kN) & 3][(i - kN) >> 2] ^ t;
            } else if (kN > 6 & (i % kN) == 4) {
                t = keyOut[(i - 1) & 3][(i - 1) >> 2]; 
                // AES SubWord
                t =   ((AES_S[(t >>> 24) & 0xFF]) & 0xFF) << 24
                    | ((AES_S[(t >>> 16) & 0xFF]) & 0xFF) << 16
                    | ((AES_S[(t >>>  8) & 0xFF]) & 0xFF) <<  8
                    | ((AES_S[(t       ) & 0xFF]) & 0xFF);
                keyOut[i & 3][i >> 2] = keyOut[(i - kN) & 3][(i - kN) >> 2] ^ t;
            } else {
                keyOut[i & 3][i >> 2] = keyOut[(i - kN) & 3][(i - kN) >> 2]
                                      ^ keyOut[(i -  1) & 3][(i -  1) >> 2];
            }
        }
        
        // transpose the keys
        for (int i = 0; i <= rounds; ++i) {
            keyTranspose(i);
        }
        
        init = true;
        encrypting = willEncrypt;
    }
    
    private void keyTranspose(int i) {
        a0 = key0[i]; a1 = key1[i]; a2 = key2[i]; a3 = key3[i];
        
        key0[i] = ((a0 & 0xFF000000)       ) | ((a1 & 0xFF000000) >>>  8) 
                | ((a2 & 0xFF000000) >>> 16) | ((a3 & 0xFF000000) >>> 24);
        key1[i] = ((a0 & 0x00FF0000)  <<  8) | ((a1 & 0x00FF0000)       ) 
                | ((a2 & 0x00FF0000) >>>  8) | ((a3 & 0x00FF0000) >>> 16);
        key2[i] = ((a0 & 0x0000FF00)  << 16) | ((a1 & 0x0000FF00)  <<  8) 
                | ((a2 & 0x0000FF00)       ) | ((a3 & 0x0000FF00) >>>  8);
        key3[i] = ((a0 & 0x000000FF)  << 24) | ((a1 & 0x000000FF)  << 16) 
                | ((a2 & 0x000000FF)  <<  8) | ((a3 & 0x000000FF)       );
    }

    @Override
    public void initEncrypt(byte[] key) {
        initBase(key, true);
    }

    @Override
    public void initDecrypt(byte[] key) {
        initBase(key, false);
    }
    
    /* private */ int doSubBytes(int t) {
        return ((AES_S[(t >>> 24) & 0xFF]) & 0xFF) << 24
             | ((AES_S[(t >>> 16) & 0xFF]) & 0xFF) << 16
             | ((AES_S[(t >>>  8) & 0xFF]) & 0xFF) <<  8
             | ((AES_S[(t       ) & 0xFF]) & 0xFF);
    }
    
    /* private */ int doInvSubBytes(int t) {
        return ((AES_IS[(t >>> 24) & 0xFF]) & 0xFF) << 24
             | ((AES_IS[(t >>> 16) & 0xFF]) & 0xFF) << 16
             | ((AES_IS[(t >>>  8) & 0xFF]) & 0xFF) <<  8
             | ((AES_IS[(t       ) & 0xFF]) & 0xFF);
    }
    
    /* private */ void doMixColumns() {
        // aN <- tN
        a0 = t0; a1 = t1; a2 = t2; a3 = t3;
        
        // bN <- 2tN within the Rijndael Galois field
        bm  =  t0 & 0x80808080;                                // extr hi bits
        bm |= (bm >>> 1); bm |= (bm >>> 2); bm |= (bm >>> 4);  // $80 -> $FF
        b0  = (t0 & 0x7F7F7F7F) << 1;                          // mask & shift
        b0 ^=  bm & 0x1B1B1B1B;                                // xor $1B 
        bm  =  t1 & 0x80808080;                                // extr hi bits
        bm |= (bm >>> 1); bm |= (bm >>> 2); bm |= (bm >>> 4);  // $80 -> $FF
        b1  = (t1 & 0x7F7F7F7F) << 1;                          // mask & shift
        b1 ^=  bm & 0x1B1B1B1B;                                // xor $1B 
        bm  =  t2 & 0x80808080;                                // extr hi bits
        bm |= (bm >>> 1); bm |= (bm >>> 2); bm |= (bm >>> 4);  // $80 -> $FF
        b2  = (t2 & 0x7F7F7F7F) << 1;                          // mask & shift
        b2 ^=  bm & 0x1B1B1B1B;                                // xor $1B 
        bm  =  t3 & 0x80808080;                                // extr hi bits
        bm |= (bm >>> 1); bm |= (bm >>> 2); bm |= (bm >>> 4);  // $80 -> $FF
        b3  = (t3 & 0x7F7F7F7F) << 1;                          // mask & shift
        b3 ^=  bm & 0x1B1B1B1B;                                // xor $1B 
        
        t0 = b0 ^ a3 ^ a2 ^ b1 ^ a1;
        t1 = b1 ^ a0 ^ a3 ^ b2 ^ a2;
        t2 = b2 ^ a1 ^ a0 ^ b3 ^ a3;
        t3 = b3 ^ a2 ^ a1 ^ b0 ^ a0;
    }
    
    /* private */ void doInvMixColumns() {
        
    }

    @Override
    public byte[] process(byte[] block) {
        if (!init) {
            throw new IllegalStateException("init first");
        }
        if (block.length != getBlockSizeInBytes()) {
            throw new IllegalArgumentException("invalid block size");
        }
        
        // convert block to 4 ints
        t0 =      ((block[ 0] & 0xFF) << 24) | ((block[ 4] & 0xFF) << 16) 
                | ((block[ 8] & 0xFF) <<  8) |  (block[12] & 0xFF);
        t1 =      ((block[ 1] & 0xFF) << 24) | ((block[ 5] & 0xFF) << 16) 
                | ((block[ 9] & 0xFF) <<  8) |  (block[13] & 0xFF);
        t2 =      ((block[ 2] & 0xFF) << 24) | ((block[ 6] & 0xFF) << 16) 
                | ((block[10] & 0xFF) <<  8) |  (block[14] & 0xFF);
        t3 =      ((block[ 3] & 0xFF) << 24) | ((block[ 7] & 0xFF) << 16) 
                | ((block[11] & 0xFF) <<  8) |  (block[15] & 0xFF);
        
        if (encrypting) {
            for (int i = 0; i < rounds - 1; ++i) {
                // AddRoundKey
                t0 ^= key0[i]; t1 ^= key1[i]; t2 ^= key2[i]; t3 ^= key3[i];
                // SubBytes
                t0 = doSubBytes(t0); t1 = doSubBytes(t1);
                t2 = doSubBytes(t2); t3 = doSubBytes(t3);
                // ShiftRows
                t1 = (t1 <<  8) | (t1 >>> 24);
                t2 = (t2 << 16) | (t2 >>> 16);
                t3 = (t3 << 24) | (t3 >>>  8);
                // MixColumns
                doMixColumns();
            }

            // pre-final AddRoundKey
            t0 ^= key0[rounds - 1]; t1 ^= key1[rounds - 1]; 
            t2 ^= key2[rounds - 1]; t3 ^= key3[rounds - 1];
            // SubBytes
            t0 = doSubBytes(t0); t1 = doSubBytes(t1);
            t2 = doSubBytes(t2); t3 = doSubBytes(t3);
            // ShiftRows
            t1 = (t1 <<  8) | (t1 >>> 24);
            t2 = (t2 << 16) | (t2 >>> 16);
            t3 = (t3 << 24) | (t3 >>>  8);
        } else {
            for (int i = 0; i < rounds - 1; ++i) {
                // AddRoundKey
                t0 ^= key0[i]; t1 ^= key1[i]; t2 ^= key2[i]; t3 ^= key3[i];
                // inverse SubBytes
                t0 = doInvSubBytes(t0); t1 = doInvSubBytes(t1);
                t2 = doInvSubBytes(t2); t3 = doInvSubBytes(t3);
                // inverse ShiftRows
                t1 = (t1 << 24) | (t1 >>>  8);
                t2 = (t2 << 16) | (t2 >>> 16);
                t3 = (t3 <<  8) | (t3 >>> 24);
                // inverse MixColumns
                doInvMixColumns();
            }
            
            // pre-final AddRoundKey
            t0 ^= key0[rounds - 1]; t1 ^= key1[rounds - 1]; 
            t2 ^= key2[rounds - 1]; t3 ^= key3[rounds - 1];
            // inverse SubBytes
            t0 = doInvSubBytes(t0); t1 = doInvSubBytes(t1);
            t2 = doInvSubBytes(t2); t3 = doInvSubBytes(t3);
            // inverse ShiftRows
            t1 = (t1 << 24) | (t1 >>>  8);
            t2 = (t2 << 16) | (t2 >>> 16);
            t3 = (t3 <<  8) | (t3 >>> 24);
        }
        
        // final AddRoundKey
        t0 ^= key0[rounds]; t1 ^= key1[rounds]; 
        t2 ^= key2[rounds]; t3 ^= key3[rounds];
        
        // convert ints back to block
        block[ 0] = (byte) (t0 >>> 24); block[ 1] = (byte) (t1 >>> 24);
        block[ 2] = (byte) (t2 >>> 24); block[ 3] = (byte) (t3 >>> 24);
        block[ 4] = (byte) (t0 >>> 16); block[ 5] = (byte) (t1 >>> 16);
        block[ 6] = (byte) (t2 >>> 16); block[ 7] = (byte) (t3 >>> 16);
        block[ 8] = (byte) (t0 >>>  8); block[ 9] = (byte) (t1 >>>  8);
        block[10] = (byte) (t2 >>>  8); block[11] = (byte) (t3 >>>  8);
        block[12] = (byte) (t0       ); block[13] = (byte) (t1       );
        block[14] = (byte) (t2       ); block[15] = (byte) (t3       );
        
        return block;
    }

    @Override
    public void finish() {
        if (!init) {
            throw new IllegalStateException("already finished");
        }
        
        Utils.destroyArray(key0);
        Utils.destroyArray(key1);
        Utils.destroyArray(key2);
        Utils.destroyArray(key3);
        rounds = 0;
        t0 = t1 = t2 = t3 = 0;
        a0 = a1 = a2 = a3 = 0;
        b0 = b1 = b2 = b3 = 0;
        init = false;
    }

}
