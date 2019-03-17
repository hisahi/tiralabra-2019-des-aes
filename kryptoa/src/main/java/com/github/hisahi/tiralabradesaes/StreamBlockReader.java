
package com.github.hisahi.tiralabradesaes; 

import java.io.IOException;
import java.io.InputStream;

/**
 * Represents a blocked version of InputStream that converts a stream into blocks suitable for encryption and decryption with block ciphers.
 */
public class StreamBlockReader {
    private InputStream stream;
    private byte[] buffer;
    private int blockPointer;
    private boolean reachedEof;
    
    /**
     * Creates a new BlockInputStream from an existing InputStream and a size of the block in bytes (* 8 for size in bits).
     * 
     * @param inp The InputStream to wrap.
     * @param byteSize The size of the block in bytes.
     */
    public StreamBlockReader(InputStream inp, int byteSize) {
        stream = inp;
        buffer = new byte[byteSize];
        blockPointer = 0;
        reachedEof = false;
    }
    
    /**
     * Reads the next block from the stream. The block will be padded to the 
     * given size, or null if the end-of-stream has been reached. Note that the
     * byte array will be overwritten by this function, as the class only
     * maintains a single buffer.
     * 
     * @return The next block, or null if the end of stream has been reached.
     * @throws IOException If the underlying InputStream fails to read.
     */
    public byte[] nextBlock() throws IOException {
        if (reachedEof) {
            // EOF of underlying stream
            return null;
        }
        
        // read until the block is full or we reach EOF
        int read;
        while (blockPointer < buffer.length) {
            read = stream.read(buffer, blockPointer, buffer.length - blockPointer);
            if (read < 0) {
                break;
            }
            blockPointer += read;
        }
        
        /* at this point blockPointer is either buffer.length or less if EOF */
        if (blockPointer == 0) { // EOF exactly to block boundaries
            // PKCS padding; give empty block with bytes representing block length
            for (int i = 0; i < buffer.length; ++i) {
                buffer[i] = (byte) buffer.length;
            }
            reachedEof = true;
        } else if (blockPointer < buffer.length) {
            // PKCS padding; pad rest of block
            byte addPadding = (byte) (buffer.length - blockPointer);
            for (int i = blockPointer; i < buffer.length; ++i) {
                buffer[i] = addPadding;
            }
            reachedEof = true;
        } else {
            // reset for next block
            blockPointer = 0;
        }
        
        return buffer;
    }
}