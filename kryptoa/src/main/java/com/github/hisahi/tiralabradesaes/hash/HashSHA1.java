
package com.github.hisahi.tiralabradesaes.hash; 

import java.util.Arrays;

/**
 * Implements SHA-1, or Secure Hash Algorithm 1.
 */
public class HashSHA1 implements IHashFunction {
    // temporary variables
    private final int[] w = new int[80];
    private final byte[] resHash = new byte[20];
    private int h0, h1, h2, h3, h4, tmp;
    private int a, b, c, d, e, f, k, n;
    private long lengthInBits;
    private byte[] src;

    @Override
    public int getHashLength() {
        return 20;
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
        
        // initial values for h0, h1, h2, h3, h4
        h0 = 0x67452301; h1 = 0xEFCDAB89; h2 = 0x98BADCFE;
        h3 = 0x10325476; h4 = 0xC3D2E1F0;
        
        for (int i = 0; i < n; i += 64) {
            for (int j = 0; j < 16; ++j) {
                w[j] = ((0xFF & src[i + (j << 2) + 0]) << 24) 
                     | ((0xFF & src[i + (j << 2) + 1]) << 16)
                     | ((0xFF & src[i + (j << 2) + 2]) <<  8) 
                     | ((0xFF & src[i + (j << 2) + 3])      );
            }
            
            for (int j = 16; j < 80; ++j) {
                w[j] = w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16];
                w[j] = (w[j] << 1) | (w[j] >>> 31); // 1*ROL
            }
            
            // get a, b, c, d, e from h0, h1, h2, h3, h4
            a = h0; b = h1; c = h2; d = h3; e = h4;
             
            for (int j = 0; j < 80; ++j) {
                // f, k depend on the round
                if (j < 20) {
                    f = (b & c) | ((~b) & d);
                    k = 0x5A827999;
                } else if (j < 40) {
                    f = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                } else if (j < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                } else {
                    f = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }
                
                tmp = ((a << 5) | (a >>> 27)) + f + e + k + w[j];
                e = d; d = c; c = ((b << 30) | (b >>> 2)); b = a; a = tmp;
            }
             
            // add a, b, c, d, e to h0, h1, h2, h3, h4
            h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;
        } 
        
        // write h0, h1, h2, h3, h4 to resHash
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
        return resHash;
    }
    
    @Override
    public void reset() {
        h0 = h1 = h2 = h3 = h4 = tmp = a = b = c = d = e = f = k = n = 0;
        lengthInBits = 0L;
        Arrays.fill(w, 0);
        Arrays.fill(src, (byte) 0);
        Arrays.fill(resHash, (byte) 0);
    }

}
