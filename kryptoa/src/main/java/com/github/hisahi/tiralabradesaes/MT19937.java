
package com.github.hisahi.tiralabradesaes; 

/**
 * A MT19937 (Mersenne Twister) random number generator.
 */
public class MT19937 {
    // MT19937 constants
    private static final int W = 32;
    private static final int N = 624;
    private static final int M = 397;
    private static final int R = 31;
    private static final int A = 0x9908B0DF;
    private static final int U = 11;
    private static final int S = 7;
    private static final int B = 0x9D2C5680;
    private static final int T = 15;
    private static final int C = 0xEFC60000;
    private static final int L = 18;
    private static final int F = 1812433253;
    private static final int MASK_LO = (1 << R) - 1;
    private static final int MASK_HI = -1 ^ MASK_LO;
    
    private boolean seeded = false;
    private int index = N;
    private int[] mt = new int[N];
    
    private int getDefaultSeed() {
        int x = (int) System.currentTimeMillis();
        long y = System.nanoTime();
        while ((y & 1) == 0)
            y >>>= 1;
        return x ^ (int) y;
    }
    
    /**
     * Sets the new seed for the Mersenne Twister.
     * 
     * @param seed The new seed to use.
     */
    public void setSeed(int seed) {
        seeded = true;
        index = N;
        mt[0] = seed;
        
        for (int i = 1; i < N; ++i) {
            mt[i] = F * (mt[i - 1] ^ (mt[i - 1] >>> (W - 2))) + i;
        }
    }
    
    private void twist() {
        int x, xA;
        for (int i = 0; i < N; ++i) {
            x = (mt[i] & MASK_HI) | (mt[(i + 1) % N] & MASK_LO);
            xA = (x >>> 1) ^ (A & -(x & 1));
            mt[i] = mt[(i + M) % N] ^ xA;
        }
        index = 0;
    }
    
    /**
     * Returns the next random number from the generator.
     * 
     * @return The next random number as a 32-bit int.
     */
    public int nextInt() {
        if (index >= N) {
            if (!seeded) {
                setSeed(getDefaultSeed());
            }
            twist();
        }
        
        int y = mt[index++];
        y ^= (y >>> U);
        y ^= (y  << S) & B;
        y ^= (y  << T) & C;
        y ^= (y >>> L);
        return y;
    }
    
    /**
     * Fills the given byte array with random bytes.
     * 
     * @param res The byte array to fill.
     */
    public void nextBytes(byte[] res) {
        int n;
        for (int i = 0; i < res.length; i += 4) {
            n = nextInt();
            res[i    ] = (byte) (n >> 24);
            if (i + 1 < res.length)
                res[i + 1] = (byte) (n >> 16);
            if (i + 2 < res.length)
                res[i + 2] = (byte) (n >>  8);
            if (i + 3 < res.length)
                res[i + 3] = (byte) (n      );
        }
    }
}
