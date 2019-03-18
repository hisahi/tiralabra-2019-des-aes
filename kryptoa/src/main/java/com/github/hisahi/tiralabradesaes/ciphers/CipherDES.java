
package com.github.hisahi.tiralabradesaes.ciphers; 

import com.github.hisahi.tiralabradesaes.Utils;
import java.util.Arrays;

public class CipherDES implements IBlockCipher {
    // initial permutation (IP), encodes bit positions
    private static final int[] IP_PERM = { 6, 14, 22, 30, 38, 46, 54, 62, 4, 12, 20, 28, 36, 44, 52, 60, 2, 10, 18, 26, 34, 42, 50, 58, 0, 8, 16, 24, 32, 40, 48, 56, 7, 15, 23, 31, 39, 47, 55, 63, 5, 13, 21, 29, 37, 45, 53, 61, 3, 11, 19, 27, 35, 43, 51, 59, 1, 9, 17, 25, 33, 41, 49, 57 };
    // final permutation (FP), encodes bit positions; inverse of IP
    private static final int[] FP_PERM = { 24, 56, 16, 48, 8, 40, 0, 32, 25, 57, 17, 49, 9, 41, 1, 33, 26, 58, 18, 50, 10, 42, 2, 34, 27, 59, 19, 51, 11, 43, 3, 35, 28, 60, 20, 52, 12, 44, 4, 36, 29, 61, 21, 53, 13, 45, 5, 37, 30, 62, 22, 54, 14, 46, 6, 38, 31, 63, 23, 55, 15, 47, 7, 39 };
    // PC-1 permutation for key
    private static final int[] PC1_PERM = { 56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 7, 15, 23, 31, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3, 39, 47, 55, 63 };
    
    // how many times to rotate the keys while generating round subkeys
    private static final int[] KEY_ROTS = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
    
    // S-boxes, one for each nibble, with 6->4 bits
    private static final long[] SBOX_1 = { 0xe0000000L, 0x00000000L, 0x40000000L, 0xf0000000L, 0xd0000000L, 0x70000000L, 0x10000000L, 0x40000000L, 0x20000000L, 0xe0000000L, 0xf0000000L, 0x20000000L, 0xb0000000L, 0xd0000000L, 0x80000000L, 0x10000000L, 0x30000000L, 0xa0000000L, 0xa0000000L, 0x60000000L, 0x60000000L, 0xc0000000L, 0xc0000000L, 0xb0000000L, 0x50000000L, 0x90000000L, 0x90000000L, 0x50000000L, 0x00000000L, 0x30000000L, 0x70000000L, 0x80000000L, 0x40000000L, 0xf0000000L, 0x10000000L, 0xc0000000L, 0xe0000000L, 0x80000000L, 0x80000000L, 0x20000000L, 0xd0000000L, 0x40000000L, 0x60000000L, 0x90000000L, 0x20000000L, 0x10000000L, 0xb0000000L, 0x70000000L, 0xf0000000L, 0x50000000L, 0xc0000000L, 0xb0000000L, 0x90000000L, 0x30000000L, 0x70000000L, 0xe0000000L, 0x30000000L, 0xa0000000L, 0xa0000000L, 0x00000000L, 0x50000000L, 0x60000000L, 0x00000000L, 0xd0000000L };
    private static final long[] SBOX_2 = { 0x0f000000L, 0x03000000L, 0x01000000L, 0x0d000000L, 0x08000000L, 0x04000000L, 0x0e000000L, 0x07000000L, 0x06000000L, 0x0f000000L, 0x0b000000L, 0x02000000L, 0x03000000L, 0x08000000L, 0x04000000L, 0x0e000000L, 0x09000000L, 0x0c000000L, 0x07000000L, 0x00000000L, 0x02000000L, 0x01000000L, 0x0d000000L, 0x0a000000L, 0x0c000000L, 0x06000000L, 0x00000000L, 0x09000000L, 0x05000000L, 0x0b000000L, 0x0a000000L, 0x05000000L, 0x00000000L, 0x0d000000L, 0x0e000000L, 0x08000000L, 0x07000000L, 0x0a000000L, 0x0b000000L, 0x01000000L, 0x0a000000L, 0x03000000L, 0x04000000L, 0x0f000000L, 0x0d000000L, 0x04000000L, 0x01000000L, 0x02000000L, 0x05000000L, 0x0b000000L, 0x08000000L, 0x06000000L, 0x0c000000L, 0x07000000L, 0x06000000L, 0x0c000000L, 0x09000000L, 0x00000000L, 0x03000000L, 0x05000000L, 0x02000000L, 0x0e000000L, 0x0f000000L, 0x09000000L };
    private static final long[] SBOX_3 = { 0x00a00000L, 0x00d00000L, 0x00000000L, 0x00700000L, 0x00900000L, 0x00000000L, 0x00e00000L, 0x00900000L, 0x00600000L, 0x00300000L, 0x00300000L, 0x00400000L, 0x00f00000L, 0x00600000L, 0x00500000L, 0x00a00000L, 0x00100000L, 0x00200000L, 0x00d00000L, 0x00800000L, 0x00c00000L, 0x00500000L, 0x00700000L, 0x00e00000L, 0x00b00000L, 0x00c00000L, 0x00400000L, 0x00b00000L, 0x00200000L, 0x00f00000L, 0x00800000L, 0x00100000L, 0x00d00000L, 0x00100000L, 0x00600000L, 0x00a00000L, 0x00400000L, 0x00d00000L, 0x00900000L, 0x00000000L, 0x00800000L, 0x00600000L, 0x00f00000L, 0x00900000L, 0x00300000L, 0x00800000L, 0x00000000L, 0x00700000L, 0x00b00000L, 0x00400000L, 0x00100000L, 0x00f00000L, 0x00200000L, 0x00e00000L, 0x00c00000L, 0x00300000L, 0x00500000L, 0x00b00000L, 0x00a00000L, 0x00500000L, 0x00e00000L, 0x00200000L, 0x00700000L, 0x00c00000L };
    private static final long[] SBOX_4 = { 0x00070000L, 0x000d0000L, 0x000d0000L, 0x00080000L, 0x000e0000L, 0x000b0000L, 0x00030000L, 0x00050000L, 0x00000000L, 0x00060000L, 0x00060000L, 0x000f0000L, 0x00090000L, 0x00000000L, 0x000a0000L, 0x00030000L, 0x00010000L, 0x00040000L, 0x00020000L, 0x00070000L, 0x00080000L, 0x00020000L, 0x00050000L, 0x000c0000L, 0x000b0000L, 0x00010000L, 0x000c0000L, 0x000a0000L, 0x00040000L, 0x000e0000L, 0x000f0000L, 0x00090000L, 0x000a0000L, 0x00030000L, 0x00060000L, 0x000f0000L, 0x00090000L, 0x00000000L, 0x00000000L, 0x00060000L, 0x000c0000L, 0x000a0000L, 0x000b0000L, 0x00010000L, 0x00070000L, 0x000d0000L, 0x000d0000L, 0x00080000L, 0x000f0000L, 0x00090000L, 0x00010000L, 0x00040000L, 0x00030000L, 0x00050000L, 0x000e0000L, 0x000b0000L, 0x00050000L, 0x000c0000L, 0x00020000L, 0x00070000L, 0x00080000L, 0x00020000L, 0x00040000L, 0x000e0000L };
    private static final long[] SBOX_5 = { 0x00002000L, 0x0000e000L, 0x0000c000L, 0x0000b000L, 0x00004000L, 0x00002000L, 0x00001000L, 0x0000c000L, 0x00007000L, 0x00004000L, 0x0000a000L, 0x00007000L, 0x0000b000L, 0x0000d000L, 0x00006000L, 0x00001000L, 0x00008000L, 0x00005000L, 0x00005000L, 0x00000000L, 0x00003000L, 0x0000f000L, 0x0000f000L, 0x0000a000L, 0x0000d000L, 0x00003000L, 0x00000000L, 0x00009000L, 0x0000e000L, 0x00008000L, 0x00009000L, 0x00006000L, 0x00004000L, 0x0000b000L, 0x00002000L, 0x00008000L, 0x00001000L, 0x0000c000L, 0x0000b000L, 0x00007000L, 0x0000a000L, 0x00001000L, 0x0000d000L, 0x0000e000L, 0x00007000L, 0x00002000L, 0x00008000L, 0x0000d000L, 0x0000f000L, 0x00006000L, 0x00009000L, 0x0000f000L, 0x0000c000L, 0x00000000L, 0x00005000L, 0x00009000L, 0x00006000L, 0x0000a000L, 0x00003000L, 0x00004000L, 0x00000000L, 0x00005000L, 0x0000e000L, 0x00003000L };
    private static final long[] SBOX_6 = { 0x00000c00L, 0x00000a00L, 0x00000100L, 0x00000f00L, 0x00000a00L, 0x00000400L, 0x00000f00L, 0x00000200L, 0x00000900L, 0x00000700L, 0x00000200L, 0x00000c00L, 0x00000600L, 0x00000900L, 0x00000800L, 0x00000500L, 0x00000000L, 0x00000600L, 0x00000d00L, 0x00000100L, 0x00000300L, 0x00000d00L, 0x00000400L, 0x00000e00L, 0x00000e00L, 0x00000000L, 0x00000700L, 0x00000b00L, 0x00000500L, 0x00000300L, 0x00000b00L, 0x00000800L, 0x00000900L, 0x00000400L, 0x00000e00L, 0x00000300L, 0x00000f00L, 0x00000200L, 0x00000500L, 0x00000c00L, 0x00000200L, 0x00000900L, 0x00000800L, 0x00000500L, 0x00000c00L, 0x00000f00L, 0x00000300L, 0x00000a00L, 0x00000700L, 0x00000b00L, 0x00000000L, 0x00000e00L, 0x00000400L, 0x00000100L, 0x00000a00L, 0x00000700L, 0x00000100L, 0x00000600L, 0x00000d00L, 0x00000000L, 0x00000b00L, 0x00000800L, 0x00000600L, 0x00000d00L };
    private static final long[] SBOX_7 = { 0x00000040L, 0x000000d0L, 0x000000b0L, 0x00000000L, 0x00000020L, 0x000000b0L, 0x000000e0L, 0x00000070L, 0x000000f0L, 0x00000040L, 0x00000000L, 0x00000090L, 0x00000080L, 0x00000010L, 0x000000d0L, 0x000000a0L, 0x00000030L, 0x000000e0L, 0x000000c0L, 0x00000030L, 0x00000090L, 0x00000050L, 0x00000070L, 0x000000c0L, 0x00000050L, 0x00000020L, 0x000000a0L, 0x000000f0L, 0x00000060L, 0x00000080L, 0x00000010L, 0x00000060L, 0x00000010L, 0x00000060L, 0x00000040L, 0x000000b0L, 0x000000b0L, 0x000000d0L, 0x000000d0L, 0x00000080L, 0x000000c0L, 0x00000010L, 0x00000030L, 0x00000040L, 0x00000070L, 0x000000a0L, 0x000000e0L, 0x00000070L, 0x000000a0L, 0x00000090L, 0x000000f0L, 0x00000050L, 0x00000060L, 0x00000000L, 0x00000080L, 0x000000f0L, 0x00000000L, 0x000000e0L, 0x00000050L, 0x00000020L, 0x00000090L, 0x00000030L, 0x00000020L, 0x000000c0L };
    private static final long[] SBOX_8 = { 0x0000000dL, 0x00000001L, 0x00000002L, 0x0000000fL, 0x00000008L, 0x0000000dL, 0x00000004L, 0x00000008L, 0x00000006L, 0x0000000aL, 0x0000000fL, 0x00000003L, 0x0000000bL, 0x00000007L, 0x00000001L, 0x00000004L, 0x0000000aL, 0x0000000cL, 0x00000009L, 0x00000005L, 0x00000003L, 0x00000006L, 0x0000000eL, 0x0000000bL, 0x00000005L, 0x00000000L, 0x00000000L, 0x0000000eL, 0x0000000cL, 0x00000009L, 0x00000007L, 0x00000002L, 0x00000007L, 0x00000002L, 0x0000000bL, 0x00000001L, 0x00000004L, 0x0000000eL, 0x00000001L, 0x00000007L, 0x00000009L, 0x00000004L, 0x0000000cL, 0x0000000aL, 0x0000000eL, 0x00000008L, 0x00000002L, 0x0000000dL, 0x00000000L, 0x0000000fL, 0x00000006L, 0x0000000cL, 0x0000000aL, 0x00000009L, 0x0000000dL, 0x00000000L, 0x0000000fL, 0x00000003L, 0x00000003L, 0x00000005L, 0x00000005L, 0x00000006L, 0x00000008L, 0x0000000bL };
    
    private boolean init = false;
    private boolean encrypting = false;
    
    // round subkeys
    private long[] keysched;
    
    // temp variables
    private byte[] tmpblk;
    private long tmp, vas, oik, E;
    private int j;
    
    public CipherDES() {
        tmpblk = new byte[getBlockSizeInBytes()];
    }

    @Override
    public int getBlockSizeInBytes() {
        return 8;
    }
    
    @Override
    public boolean isValidKeySize(int bytes) {
        return bytes == 8;
    }
    
    private void initBase(byte[] key) {
        if (init) {
            throw new IllegalStateException("already init");
        }
        // at this point we assume key is 64-bit with odd parity. you can use
        // Utils.prepareDESKey to prepare from 56-bit 7-byte array key to
        // 64-bit 8-byte array key.
        if (key.length != 8) {
            throw new IllegalArgumentException("key must be 64-bit, 8 bytes, with odd parity");
        }
        
        if (!validParity(key)) {
            //throw new IllegalArgumentException("key has invalid parity, must have odd parity");
            // no, invalid parity is fine for now
        }
        
        key = Arrays.copyOf(key, key.length);
        
        long a1, a2, a3, a4, a5, a6, a7, a8;
        
        // initial key permutation (PC1)
        doPermRev(key, PC1_PERM);
        
        // mask out parity bits
        key[3] &= 0xF0;
        key[7] &= 0xF0;
        
        // split into two 28-bit subkeys
        long avainvas = (0xFFFFFFF0L & (((key[0] & 0xFF) << 24) 
                                     |  ((key[1] & 0xFF) << 16) 
                                     |  ((key[2] & 0xFF) << 8) 
                                     |   (key[3] & 0xFF)));
        long avainoik = (0xFFFFFFF0L & (((key[4] & 0xFF) << 24) 
                                     |  ((key[5] & 0xFF) << 16) 
                                     |  ((key[6] & 0xFF) << 8) 
                                     |   (key[7] & 0xFF)));
        keysched = new long[16];
        
        // generate key schedule
        for (int i = 0; i < 16; ++i) {
            // rotate keys
            avainvas = ((avainvas << KEY_ROTS[i]) | (avainvas >>> (28 - KEY_ROTS[i]))) & 0xFFFFFFF0L;
            avainoik = ((avainoik << KEY_ROTS[i]) | (avainoik >>> (28 - KEY_ROTS[i]))) & 0xFFFFFFF0L;
            
            // generate subkey (lots of obscure bit math but this encodes PC-2)
            a1 = extractPC2Bits(avainvas, 18, 15, 21,  8, 31, 27);
            a2 = extractPC2Bits(avainvas, 29,  4, 17, 26, 11, 22);
            a3 = extractPC2Bits(avainvas,  9, 13, 20, 28,  6, 24);
            a4 = extractPC2Bits(avainvas, 16, 25,  5, 12, 19, 30);
            a5 = extractPC2Bits(avainoik, 19,  8, 29, 23, 13,  5);
            a6 = extractPC2Bits(avainoik, 30, 20,  9, 15, 27, 12);
            a7 = extractPC2Bits(avainoik, 16, 11, 21,  4, 26,  7);
            a8 = extractPC2Bits(avainoik, 14, 18, 10, 24, 31, 28);
            
            // reverse subkey order when decrypting
            keysched[encrypting ? i : (15 - i)] 
                        = (a1 << 42) | (a2 << 36) | (a3 << 30) | (a4 << 24)
                        | (a5 << 18) | (a6 << 12) | (a7 <<  6) | (a8      );
        }
        a1 = a2 = a3 = a4 = a5 = a6 = a7 = a8 = 0;
        init = true;
    }

    // check if bits 7, 15, 23... have proper parity
    private boolean validParity(byte[] key) {
        tmp = (((long) key[0] & 0xFF) << 56) 
            | (((long) key[1] & 0xFF) << 48) 
            | (((long) key[2] & 0xFF) << 40) 
            | (((long) key[3] & 0xFF) << 32) 
            | (((long) key[4] & 0xFF) << 24) 
            | (((long) key[5] & 0xFF) << 16) 
            | (((long) key[6] & 0xFF) <<  8) 
            | (((long) key[7] & 0xFF));
        
        for (int i = 1; i < 8; ++i) {
            tmp ^= (tmp << i);
        }
        
        return (tmp & 0x0101010101010101L) == 0x0101010101010101L;
    }
        
    private long extractPC2Bits(long key, int a, int b, int c, int d, int e, int f) {
        return   ((key >> a) & 1L) << 5
               | ((key >> b) & 1L) << 4
               | ((key >> c) & 1L) << 3
               | ((key >> d) & 1L) << 2
               | ((key >> e) & 1L) << 1
               | ((key >> f) & 1L);
    }

    @Override
    public void initEncrypt(byte[] key) {
        encrypting = true;
        initBase(key);
    }

    @Override
    public void initDecrypt(byte[] key) {
        encrypting = false;
        initBase(key);
    }

    @Override
    public void finish() {
        if (!init) {
            throw new IllegalStateException("already finished");
        }
        Utils.destroyArray(tmpblk);
        Arrays.fill(keysched, (long) -1);
        vas = oik = E = j = 0;
        init = false;
    }

    private void doPerm(byte[] block, int[] perm) {
        System.arraycopy(block, 0, tmpblk, 0, 8);
        Arrays.fill(block, (byte) 0);
        
        for (int i = 0; i < 64; ++i) {
            j = perm[i];
            block[i >> 3] |= (long) ((tmpblk[j >> 3] >> (j & 7)) & 1L) << (i & 7);
        }
    }

    private void doPermRev(byte[] block, int[] perm) {
        System.arraycopy(block, 0, tmpblk, 0, 8);
        Arrays.fill(block, (byte) 0);
        
        for (int i = 0; i < 64; ++i) {
            j = perm[i];
            block[i >> 3] |= (long) ((tmpblk[j >> 3] >> (7 ^ j & 7)) & 1L) << ((7 ^ i) & 7);
        }
    }
    
    private long doubleExpand(long l) {
        return ((l & (63L << 42)) << 14L)
             | ((l & (63L << 36)) << 12L)
             | ((l & (63L << 30)) << 10L)
             | ((l & (63L << 24)) <<  8L)
             | ((l & (63L << 18)) <<  6L)
             | ((l & (63L << 12)) <<  4L)
             | ((l & (63L <<  6)) <<  2L)
             | ((l & (63)));
    }
    
    private int feistel(int round, long val) {
        // expansion
        E =       ((val & 0xF8000000L) << 15L)
                | ((val & 0x1F800000L) << 13L)
                | ((val & 0x01F80000L) << 11L)
                | ((val & 0x001F8000L) <<  9L) 
                | ((val & 0x0001F800L) <<  7L)  
                | ((val & 0x00001F80L) <<  5L)
                | ((val & 0x000001F8L) <<  3L)
                | ((val & 0x0000001FL) <<  1L)
                | ((val & 1L) << 47L) | ((val & 0x80000000L) >> 31L);
        
        // key mixing
        E ^= keysched[round];
        
        // substitution
        E =   SBOX_1[(int) (E >> 42) & 0x3F]
            | SBOX_2[(int) (E >> 36) & 0x3F]
            | SBOX_3[(int) (E >> 30) & 0x3F]
            | SBOX_4[(int) (E >> 24) & 0x3F]
            | SBOX_5[(int) (E >> 18) & 0x3F]
            | SBOX_6[(int) (E >> 12) & 0x3F]
            | SBOX_7[(int) (E >>  6) & 0x3F]
            | SBOX_8[(int) (E      ) & 0x3F];
        
        // permutation (encodes the P block)
        E =   (((E >>  7) & 1)      ) | (((E >> 28) & 1) <<  1)
            | (((E >> 21) & 1) <<  2) | (((E >> 10) & 1) <<  3)
            | (((E >> 26) & 1) <<  4) | (((E >>  2) & 1) <<  5)
            | (((E >> 19) & 1) <<  6) | (((E >> 13) & 1) <<  7)
            | (((E >> 23) & 1) <<  8) | (((E >> 29) & 1) <<  9)
            | (((E >>  5) & 1) << 10) | (((E      ) & 1) << 11)
            | (((E >> 18) & 1) << 12) | (((E >>  8) & 1) << 13)
            | (((E >> 24) & 1) << 14) | (((E >> 30) & 1) << 15)
            | (((E >> 22) & 1) << 16) | (((E >>  1) & 1) << 17)
            | (((E >> 14) & 1) << 18) | (((E >> 27) & 1) << 19)
            | (((E >>  6) & 1) << 20) | (((E >>  9) & 1) << 21)
            | (((E >> 17) & 1) << 22) | (((E >> 31) & 1) << 23)
            | (((E >> 15) & 1) << 24) | (((E >>  4) & 1) << 25)
            | (((E >> 20) & 1) << 26) | (((E >>  3) & 1) << 27)
            | (((E >> 11) & 1) << 28) | (((E >> 12) & 1) << 29)
            | (((E >> 25) & 1) << 30) | (((E >> 16) & 1) << 31);
            
        return (int) E;
    }
    
    @Override
    public byte[] process(byte[] block) {
        if (block.length != getBlockSizeInBytes()) {
            throw new IllegalArgumentException("invalid block size");
        }
        
        // IP
        doPerm(block, IP_PERM);
        
        // convert to long
        vas = (((long) block[0] & 0xFF) << 24) 
            | (((long) block[1] & 0xFF) << 16) 
            | (((long) block[2] & 0xFF) <<  8) 
            | (((long) block[3] & 0xFF));
        oik = (((long) block[4] & 0xFF) << 24) 
            | (((long) block[5] & 0xFF) << 16) 
            | (((long) block[6] & 0xFF) <<  8) 
            | (((long) block[7] & 0xFF));
        
        // rounds. unroll for performance
        vas ^= feistel( 0, oik); oik ^= feistel( 1, vas);
        vas ^= feistel( 2, oik); oik ^= feistel( 3, vas);
        vas ^= feistel( 4, oik); oik ^= feistel( 5, vas);
        vas ^= feistel( 6, oik); oik ^= feistel( 7, vas);
        vas ^= feistel( 8, oik); oik ^= feistel( 9, vas);
        vas ^= feistel(10, oik); oik ^= feistel(11, vas);
        vas ^= feistel(12, oik); oik ^= feistel(13, vas);
        vas ^= feistel(14, oik); oik ^= feistel(15, vas);
        
        block[0] = (byte) ((oik >> 24) & 0xFF);
        block[1] = (byte) ((oik >> 16) & 0xFF);
        block[2] = (byte) ((oik >>  8) & 0xFF);
        block[3] = (byte) ((oik      ) & 0xFF);
        block[4] = (byte) ((vas >> 24) & 0xFF);
        block[5] = (byte) ((vas >> 16) & 0xFF);
        block[6] = (byte) ((vas >>  8) & 0xFF);
        block[7] = (byte) ((vas      ) & 0xFF);
        
        // FP
        doPerm(block, FP_PERM);
        
        return block;
    }
}
