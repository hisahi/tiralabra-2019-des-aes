
package com.github.hisahi.tiralabradesaes; 

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

public class HexOutputStream extends OutputStream {
    PrintStream under;

    public HexOutputStream(PrintStream out) {
        under = out;
    }

    @Override
    public void write(int b) throws IOException {
        under.print(String.format("%02X", b & 0xFF));
    }

    @Override
    public void flush() throws IOException {
        super.flush();
        under.flush();
    }

    @Override
    public void close() throws IOException {
        super.close();
        under.println();
    }

}
