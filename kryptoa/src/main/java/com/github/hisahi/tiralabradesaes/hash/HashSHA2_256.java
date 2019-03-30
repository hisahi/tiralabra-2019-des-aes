
package com.github.hisahi.tiralabradesaes.hash; 

public class HashSHA2_256 implements IHashFunction {
    // constant
    private static final int[] k = new int[] { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                                               0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                                               0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                                               0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                                               0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                                               0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                                               0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                                               0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };
    // temporary variables
    private int h0, h1, h2, h3, h4, h5, h6, h7, tmp1, tmp2;
    private int a, b, c, d, e, f, g, h, s0, s1, ch, maj, n;
    private int[] w = new int[64];
    private long lengthInBits;
    private byte[] src;
    private byte[] resHash = new byte[32];

    @Override
    public int getHashLength() {
        return 32;
    }

    @Override
    public int getBlockSize() {
        return 64;
    }

    @Override
    public byte[] computeHash(byte[] data) {
        n = (data.length + 72) & ~63;
        src = new byte[n];
        
        // data
        System.arraycopy(data, 0, src, 0, data.length);
        // padding (0's added automatically)
        src[data.length] = (byte) 0x80;
        // length (in bits!)
        lengthInBits = (long) data.length << 3;
        src[n - 4] = (byte) (lengthInBits >>> 24);
        src[n - 3] = (byte) (lengthInBits >>> 16);
        src[n - 2] = (byte) (lengthInBits >>>  8);
        src[n - 1] = (byte) (lengthInBits       );
        
        h0 = 0x6a09e667; h1 = 0xbb67ae85;
        h2 = 0x3c6ef372; h3 = 0xa54ff53a;
        h4 = 0x510e527f; h5 = 0x9b05688c;
        h6 = 0x1f83d9ab; h7 = 0x5be0cd19;
        
        for (int i = 0; i < n; i += 64) {
            for (int j = 0; j < 16; ++j) {
                w[j] = ((0xFF & src[i + (j << 2) + 0]) << 24) 
                     | ((0xFF & src[i + (j << 2) + 1]) << 16)
                     | ((0xFF & src[i + (j << 2) + 2]) <<  8) 
                     | ((0xFF & src[i + (j << 2) + 3])      );
            }
            
            for (int j = 16; j < 64; ++j) {
                a = w[j - 15]; b = w[j - 2];
                s0 = ((a << 25) | (a >>>  7)) ^ ((a << 14) | (a >>> 18))
                                              ^ (a >>>  3);
                s1 = ((b << 15) | (b >>> 17)) ^ ((b << 13) | (b >>> 19))
                                              ^ (b >>> 10);
                w[j] = w[j - 16] + s0 + w[j - 7] + s1;
            }
            
            a = h0; b = h1; c = h2; d = h3; 
            e = h4; f = h5; g = h6; h = h7;
            
            for (int j = 0; j < 64; ++j) {
                s1 = ((e << 26) | (e >>>  6)) ^ ((e << 21) | (e >>> 11)) 
                                              ^ ((e <<  7) | (e >>> 25));
                ch = (e & f) ^ ((~e) & g);
                tmp1 = h + s1 + ch + k[j] + w[j];
                
                s0 = ((a << 30) | (a >>>  2)) ^ ((a << 19) | (a >>> 13)) 
                                              ^ ((a << 10) | (a >>> 22));
                maj = (a & b) ^ (a & c) ^ (b & c);
                tmp2 = s0 + maj;
                
                h = g; g = f; f = e; e = tmp1 + d;
                d = c; c = b; b = a; a = tmp1 + tmp2;
            }
            
            h0 += a; h1 += b; h2 += c; h3 += d;
            h4 += e; h5 += f; h6 += g; h7 += h;
        } 
        
        // write h0..7 to resHash
        resHash[ 0] = (byte) (h0 >>> 24); resHash[ 1] = (byte) (h0 >>> 16);
        resHash[ 2] = (byte) (h0 >>>  8); resHash[ 3] = (byte) (h0       );
        resHash[ 4] = (byte) (h1 >>> 24); resHash[ 5] = (byte) (h1 >>> 16);
        resHash[ 6] = (byte) (h1 >>>  8); resHash[ 7] = (byte) (h1       );
        resHash[ 8] = (byte) (h2 >>> 24); resHash[ 9] = (byte) (h2 >>> 16);
        resHash[10] = (byte) (h2 >>>  8); resHash[11] = (byte) (h2       );
        resHash[12] = (byte) (h3 >>> 24); resHash[13] = (byte) (h3 >>> 16);
        resHash[14] = (byte) (h3 >>>  8); resHash[15] = (byte) (h3       );
        resHash[16] = (byte) (h4 >>> 24); resHash[17] = (byte) (h4 >>> 16);
        resHash[18] = (byte) (h4 >>>  8); resHash[19] = (byte) (h4       );
        resHash[20] = (byte) (h5 >>> 24); resHash[21] = (byte) (h5 >>> 16);
        resHash[22] = (byte) (h5 >>>  8); resHash[23] = (byte) (h5       );
        resHash[24] = (byte) (h6 >>> 24); resHash[25] = (byte) (h6 >>> 16);
        resHash[26] = (byte) (h6 >>>  8); resHash[27] = (byte) (h6       );
        resHash[28] = (byte) (h7 >>> 24); resHash[29] = (byte) (h7 >>> 16);
        resHash[30] = (byte) (h7 >>>  8); resHash[31] = (byte) (h7       );
        return resHash;
    }

    @Override
    public void reset() {
        h0 = h1 = h2 = h3 = h4 = h5 = h6 = h7 = tmp1 = tmp2 = 0;
        a = b = c = d = e = f = g = h = s0 = s1 = ch = maj = n = 0;
        lengthInBits = 0;
    }
    
}
