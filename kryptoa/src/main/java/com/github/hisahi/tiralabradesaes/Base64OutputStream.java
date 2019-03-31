
package com.github.hisahi.tiralabradesaes; 

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * An output stream that writes the bytes encoded as Base64 into the 
 * underlying PrintStream. When the HexOutputStream is closed, it will
 * also write a newline to the underlying PrintStream.
 */
public class Base64OutputStream extends OutputStream {
    PrintStream under;
    private byte[] buffer;
    private int bufpointer;

    public Base64OutputStream(PrintStream out) {
        under = out;
        buffer = new byte[3];
        bufpointer = 0;
    }
    
    private void writeBase64(int padding) {
        int d0 =                              ((buffer[0] & 0xFC) >>> 2);
        int d1 = ((buffer[0] & 0x03)  << 4) | ((buffer[1] & 0xF0) >>> 4);
        int d2 = ((buffer[1] & 0x0F)  << 2) | ((buffer[2] & 0xC0) >>> 6);
        int d3 = ((buffer[2] & 0x3F)      );
        
        under.print(Utils.B64_DIGITS.charAt(d0));
        under.print(Utils.B64_DIGITS.charAt(d1));
        switch (padding) {
        case 0:
            under.print(Utils.B64_DIGITS.charAt(d2));
            under.print(Utils.B64_DIGITS.charAt(d3));
            break;
        case 1:
            under.print(Utils.B64_DIGITS.charAt(d2));
            under.print(Utils.B64_DIGITS.charAt(64)); // padding
            break;
        case 2:
            under.print(Utils.B64_DIGITS.charAt(64)); // padding
            under.print(Utils.B64_DIGITS.charAt(64)); // padding
            break;
        }
    }

    @Override
    public void write(int b) throws IOException {
        buffer[bufpointer++] = (byte) b;
        if (bufpointer == buffer.length) {
            writeBase64(0);
            bufpointer = 0;
        }
    }

    @Override
    public void flush() throws IOException {
        super.flush();
        under.flush();
    }

    @Override
    public void close() throws IOException {
        // pad remaining with 0
        if (bufpointer > 0) {
            for (int i = bufpointer; i < buffer.length; ++i) {
                buffer[i] &= 0;
            }
            writeBase64(buffer.length - bufpointer);
        }
        
        // when closing stream, add a newline
        super.close();
        under.println();
    }

}
