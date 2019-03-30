
package com.github.hisahi.tiralabradesaes.hash; 

public class HashSHA2_224 extends HashSHA2_256 {
    protected byte[] resHash;
    
    public HashSHA2_224() {
        resHash = new byte[28];
    }

    @Override
    public int getHashLength() {
        return 28;
    }

    @Override
    public int getBlockSize() {
        return 64;
    }
    
    @Override
    protected void initHn() {
        h0 = 0xc1059ed8; h1 = 0x367cd507;
        h2 = 0x3070dd17; h3 = 0xf70e5939;
        h4 = 0xffc00b31; h5 = 0x68581511;
        h6 = 0x64f98fa7; h7 = 0xbefa4fa4;
    }

    @Override
    public byte[] computeHash(byte[] data) {
        initHn();
        computeHashInt(data);
        
        // write h0..6 to resHash
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
        return resHash;
    }
}
