
package com.github.hisahi.tiralabradesaes; 

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * An output stream that writes the bytes encoded as hexadecimal digits into
 * the underlying PrintStream. When the HexOutputStream is closed, it will
 * also write a newline to the underlying PrintStream.
 */
public class HexOutputStream extends OutputStream {
    PrintStream under;

    public HexOutputStream(PrintStream out) {
        under = out;
    }

    @Override
    public void write(int b) throws IOException {
        // encode to hex
        under.print(String.format("%02X", b & 0xFF));
    }

    @Override
    public void flush() throws IOException {
        super.flush();
        under.flush();
    }

    @Override
    public void close() throws IOException {
        // when closing stream, add a newline
        super.close();
        under.println();
    }

}
