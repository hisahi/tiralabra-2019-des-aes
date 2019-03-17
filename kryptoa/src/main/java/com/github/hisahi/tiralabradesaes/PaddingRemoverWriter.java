
package com.github.hisahi.tiralabradesaes; 

import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A class that writes to an OutputStream, removing PKCS padding from the blocks it has been given.
 */
public class PaddingRemoverWriter {
    private OutputStream stream;
    private byte[] buffer;
    private boolean firstBlock;
    private boolean finished;
    
    /**
     * Constructs a PaddingRemoverWriter instance from an OutputStream to write to and block size in bytes.
     * 
     * @param os The OutputStream to write to.
     * @param byteSize The block size in bytes.
     */
    public PaddingRemoverWriter(OutputStream os, int byteSize) {
        stream = os;
        buffer = new byte[byteSize];
        firstBlock = true;
        finished = false;
    }
    
    /**
     * Feeds a block of data with byteSize bytes into the stream.
     * 
     * @param block The block of data to feed.
     * @throws IOException When OutputStream to be written to throws an error.
     */
    public void feedBlock(byte[] block) throws IOException {
        if (finished) {
            throw new IllegalStateException("writer already finished");
        }
        if (block.length != buffer.length) {
            throw new IllegalArgumentException("wrong blcck size given");
        }
        
        if (!firstBlock) {
            stream.write(buffer);
        }
        System.arraycopy(block, 0, buffer, 0, buffer.length);
        firstBlock = false;
    }
    
    /**
     * To be called when there are no more blocks to feed.
     */
    public void finish() throws IOException {
        if (finished) {
            throw new IllegalStateException("writer already finished");
        }
        if (firstBlock) {
            // no blcoks given, technically invalid but let's just say it's empty
            return; // valid
        }
        
        // buffer now has last block, we need to see if it is all padding
        byte allPadding = (byte) buffer.length;
        boolean isAllPadding = true;

        for (int i = 0; i < buffer.length; ++i) {
            if (buffer[i] != allPadding) {
                isAllPadding = false;
                break;
            }
        }

        if (isAllPadding) {
            // simple case; do not feed anything
            return; // valid
        } else {
            // remove padding off the end
            byte last = buffer[buffer.length - 1];
            if (last > 0 && last < buffer.length) {
                boolean isValidPadding = true;

                for (int i = buffer.length - last + 1; i < buffer.length; ++i) {
                    if (buffer[i] != last) {
                        isValidPadding = false;
                        break;
                    }
                }

                if (isValidPadding) {
                    stream.write(buffer, 0, buffer.length - last);
                    return; // valid
                } // else invalid
            } // else invalid
        }
        // should never end up here with valid padding
        throw new IllegalStateException("invalid PKCS padding");
    }
}
