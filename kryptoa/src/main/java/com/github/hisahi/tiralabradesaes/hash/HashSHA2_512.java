
package com.github.hisahi.tiralabradesaes.hash; 

/**
 * Implements SHA-512, the version of SHA-2 that creates 512-bit hashes.
 */
public class HashSHA2_512 implements IHashFunction {
    // constant
    private static final long[] k = new long[] { 0x428a2f98d728ae22L, 0x7137449123ef65cdL, 0xb5c0fbcfec4d3b2fL, 0xe9b5dba58189dbbcL, 0x3956c25bf348b538L, 
                                                 0x59f111f1b605d019L, 0x923f82a4af194f9bL, 0xab1c5ed5da6d8118L, 0xd807aa98a3030242L, 0x12835b0145706fbeL, 
                                                 0x243185be4ee4b28cL, 0x550c7dc3d5ffb4e2L, 0x72be5d74f27b896fL, 0x80deb1fe3b1696b1L, 0x9bdc06a725c71235L, 
                                                 0xc19bf174cf692694L, 0xe49b69c19ef14ad2L, 0xefbe4786384f25e3L, 0x0fc19dc68b8cd5b5L, 0x240ca1cc77ac9c65L, 
                                                 0x2de92c6f592b0275L, 0x4a7484aa6ea6e483L, 0x5cb0a9dcbd41fbd4L, 0x76f988da831153b5L, 0x983e5152ee66dfabL, 
                                                 0xa831c66d2db43210L, 0xb00327c898fb213fL, 0xbf597fc7beef0ee4L, 0xc6e00bf33da88fc2L, 0xd5a79147930aa725L, 
                                                 0x06ca6351e003826fL, 0x142929670a0e6e70L, 0x27b70a8546d22ffcL, 0x2e1b21385c26c926L, 0x4d2c6dfc5ac42aedL, 
                                                 0x53380d139d95b3dfL, 0x650a73548baf63deL, 0x766a0abb3c77b2a8L, 0x81c2c92e47edaee6L, 0x92722c851482353bL, 
                                                 0xa2bfe8a14cf10364L, 0xa81a664bbc423001L, 0xc24b8b70d0f89791L, 0xc76c51a30654be30L, 0xd192e819d6ef5218L, 
                                                 0xd69906245565a910L, 0xf40e35855771202aL, 0x106aa07032bbd1b8L, 0x19a4c116b8d2d0c8L, 0x1e376c085141ab53L, 
                                                 0x2748774cdf8eeb99L, 0x34b0bcb5e19b48a8L, 0x391c0cb3c5c95a63L, 0x4ed8aa4ae3418acbL, 0x5b9cca4f7763e373L, 
                                                 0x682e6ff3d6b2b8a3L, 0x748f82ee5defb2fcL, 0x78a5636f43172f60L, 0x84c87814a1f0ab72L, 0x8cc702081a6439ecL, 
                                                 0x90befffa23631e28L, 0xa4506cebde82bde9L, 0xbef9a3f7b2c67915L, 0xc67178f2e372532bL, 0xca273eceea26619cL, 
                                                 0xd186b8c721c0c207L, 0xeada7dd6cde0eb1eL, 0xf57d4f7fee6ed178L, 0x06f067aa72176fbaL, 0x0a637dc5a2c898a6L, 
                                                 0x113f9804bef90daeL, 0x1b710b35131c471bL, 0x28db77f523047d84L, 0x32caab7b40c72493L, 0x3c9ebe0a15c9bebcL, 
                                                 0x431d67c49c100d4cL, 0x4cc5d4becb3e42b6L, 0x597f299cfc657e2aL, 0x5fcb6fab3ad6faecL, 0x6c44198c4a475817L };
    // temporary variables
    /**
     * Temporary variables h0-h7 used in the SHA-2 computation process.
     */
    protected long h0, h1, h2, h3, h4, h5, h6, h7;
    private long a, b, c, d, e, f, g, h, s0, s1, ch, maj, tmp1, tmp2;
    private int n;
    private long[] w = new long[80];
    private long lengthInBits;
    private byte[] src;
    /**
     * A byte array for the result hash.
     */
    protected byte[] resHash;

    public HashSHA2_512() {
        resHash = new byte[64];
    }
    
    @Override
    public int getHashLength() {
        return 64;
    }

    @Override
    public int getBlockSize() {
        return 128;
    }
    
    /**
     * Initializes the constants H0..H7. Not intended to be
     * used directly but through computeHash() or an implementation of such.
     */
    protected void initHn() {
        h0 = 0x6a09e667f3bcc908L; h1 = 0xbb67ae8584caa73bL;
        h2 = 0x3c6ef372fe94f82bL; h3 = 0xa54ff53a5f1d36f1L;
        h4 = 0x510e527fade682d1L; h5 = 0x9b05688c2b3e6c1fL;
        h6 = 0x1f83d9abfb41bd6bL; h7 = 0x5be0cd19137e2179L;
    }
    
    /**
     * Computes the actual SHA-2 hash values. Not intended to be
     * used directly but through computeHash() or an implementation of such.
     * 
     * @param data The data to compute the hash for.
     */
    protected void computeHashInt(byte[] data) {
        n = (data.length + 144) & ~127;
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
        
        for (int i = 0; i < n; i += 128) {
            for (int j = 0; j < 16; ++j) {
                w[j] = ((long) (0xFF & src[i + (j << 3) + 0]) << 56) 
                     | ((long) (0xFF & src[i + (j << 3) + 1]) << 48)
                     | ((long) (0xFF & src[i + (j << 3) + 2]) << 40) 
                     | ((long) (0xFF & src[i + (j << 3) + 3]) << 32)
                     | ((long) (0xFF & src[i + (j << 3) + 4]) << 24) 
                     | ((long) (0xFF & src[i + (j << 3) + 5]) << 16)
                     | ((long) (0xFF & src[i + (j << 3) + 6]) <<  8) 
                     | ((long) (0xFF & src[i + (j << 3) + 7])      );
            }
            
            for (int j = 16; j < 80; ++j) {
                a = w[j - 15]; b = w[j - 2];
                s0 = ((a << 63) | (a >>>  1)) ^ ((a << 56) | (a >>>  8))
                                              ^ (a >>>  7);
                s1 = ((b << 45) | (b >>> 19)) ^ ((b <<  3) | (b >>> 61))
                                              ^ (b >>>  6);
                w[j] = w[j - 16] + s0 + w[j - 7] + s1;
            }
            
            a = h0; b = h1; c = h2; d = h3; 
            e = h4; f = h5; g = h6; h = h7;
            
            for (int j = 0; j < 80; ++j) {
                s1 = ((e << 50) | (e >>> 14)) ^ ((e << 46) | (e >>> 18))
                                              ^ ((e << 23) | (e >>> 41));
                ch = (e & f) ^ ((~e) & g);
                tmp1 = h + s1 + ch + k[j] + w[j];
                
                s0 = ((a << 36) | (a >>> 28)) ^ ((a << 30) | (a >>> 34))
                                              ^ ((a << 25) | (a >>> 39));
                maj = (a & b) ^ (a & c) ^ (b & c);
                tmp2 = s0 + maj;
                
                h = g; g = f; f = e; e = tmp1 + d;
                d = c; c = b; b = a; a = tmp1 + tmp2;
            }
            
            h0 += a; h1 += b; h2 += c; h3 += d;
            h4 += e; h5 += f; h6 += g; h7 += h;
        } 
    }

    @Override
    public byte[] computeHash(byte[] data) {
        initHn();
        computeHashInt(data);
        
        // write h0..7 to resHash
        resHash[ 0] = (byte) (h0 >>> 56); resHash[ 1] = (byte) (h0 >>> 48);
        resHash[ 2] = (byte) (h0 >>> 40); resHash[ 3] = (byte) (h0 >>> 32);
        resHash[ 4] = (byte) (h0 >>> 24); resHash[ 5] = (byte) (h0 >>> 16);
        resHash[ 6] = (byte) (h0 >>>  8); resHash[ 7] = (byte) (h0       );
        resHash[ 8] = (byte) (h1 >>> 56); resHash[ 9] = (byte) (h1 >>> 48);
        resHash[10] = (byte) (h1 >>> 40); resHash[11] = (byte) (h1 >>> 32);
        resHash[12] = (byte) (h1 >>> 24); resHash[13] = (byte) (h1 >>> 16);
        resHash[14] = (byte) (h1 >>>  8); resHash[15] = (byte) (h1       );
        resHash[16] = (byte) (h2 >>> 56); resHash[17] = (byte) (h2 >>> 48);
        resHash[18] = (byte) (h2 >>> 40); resHash[19] = (byte) (h2 >>> 32);
        resHash[20] = (byte) (h2 >>> 24); resHash[21] = (byte) (h2 >>> 16);
        resHash[22] = (byte) (h2 >>>  8); resHash[23] = (byte) (h2       );
        resHash[24] = (byte) (h3 >>> 56); resHash[25] = (byte) (h3 >>> 48);
        resHash[26] = (byte) (h3 >>> 40); resHash[27] = (byte) (h3 >>> 32);
        resHash[28] = (byte) (h3 >>> 24); resHash[29] = (byte) (h3 >>> 16);
        resHash[30] = (byte) (h3 >>>  8); resHash[31] = (byte) (h3       );
        resHash[32] = (byte) (h4 >>> 56); resHash[33] = (byte) (h4 >>> 48);
        resHash[34] = (byte) (h4 >>> 40); resHash[35] = (byte) (h4 >>> 32);
        resHash[36] = (byte) (h4 >>> 24); resHash[37] = (byte) (h4 >>> 16);
        resHash[38] = (byte) (h4 >>>  8); resHash[39] = (byte) (h4       );
        resHash[40] = (byte) (h5 >>> 56); resHash[41] = (byte) (h5 >>> 48);
        resHash[42] = (byte) (h5 >>> 40); resHash[43] = (byte) (h5 >>> 32);
        resHash[44] = (byte) (h5 >>> 24); resHash[45] = (byte) (h5 >>> 16);
        resHash[46] = (byte) (h5 >>>  8); resHash[47] = (byte) (h5       );
        resHash[48] = (byte) (h6 >>> 56); resHash[49] = (byte) (h6 >>> 48);
        resHash[50] = (byte) (h6 >>> 40); resHash[51] = (byte) (h6 >>> 32);
        resHash[52] = (byte) (h6 >>> 24); resHash[53] = (byte) (h6 >>> 16);
        resHash[54] = (byte) (h6 >>>  8); resHash[55] = (byte) (h6       );
        resHash[56] = (byte) (h7 >>> 56); resHash[57] = (byte) (h7 >>> 48);
        resHash[58] = (byte) (h7 >>> 40); resHash[59] = (byte) (h7 >>> 32);
        resHash[60] = (byte) (h7 >>> 24); resHash[61] = (byte) (h7 >>> 16);
        resHash[62] = (byte) (h7 >>>  8); resHash[63] = (byte) (h7       );
        return resHash;
    }

    @Override
    public void reset() {   
        h0 = h1 = h2 = h3 = h4 = h5 = h6 = h7 = tmp1 = tmp2 = 0;
        a = b = c = d = e = f = g = h = s0 = s1 = ch = maj = n = 0;
        lengthInBits = 0;
    }
    
}
