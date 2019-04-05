
package com.github.hisahi.tiralabradesaes; 

import java.io.IOException;
import java.io.OutputStream;

/**
 * An OutputStream that writes nowhere. It moves all bits to the
 * hundred-and-twenty-seventh section of the bit space.
 */
public class VoidOutputStream extends OutputStream {

    /**
     * Does nothing.
     * 
     * @param b Any number you want.
     * @throws IOException If this function can actually solve 3SAT in
     *                     polynomial time.
     */
    @Override
    public void write(int b) throws IOException {
    }

}
