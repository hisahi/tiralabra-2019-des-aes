
package com.github.hisahi.tiralabradesaes.hash; 

public class HashSHA2_384 extends HashSHA2_512 {
    protected byte[] resHash;
    
    public HashSHA2_384() {
        resHash = new byte[48];
    }
    
    @Override
    public int getHashLength() {
        return 48;
    }

    @Override
    public int getBlockSize() {
        return 128;
    }
    
    @Override
    protected void initHn() {
        h0 = 0xcbbb9d5dc1059ed8L; h1 = 0x629a292a367cd507L;
        h2 = 0x9159015a3070dd17L; h3 = 0x152fecd8f70e5939L;
        h4 = 0x67332667ffc00b31L; h5 = 0x8eb44a8768581511L;
        h6 = 0xdb0c2e0d64f98fa7L; h7 = 0x47b5481dbefa4fa4L;
    }

    @Override
    public byte[] computeHash(byte[] data) {
        initHn();
        computeHashInt(data);
        
        // write h0..5 to resHash
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
        return resHash;
    }
}
