
package com.github.hisahi.tiralabradesaes; 

import com.github.hisahi.tiralabradesaes.blockmodes.IBlockMode;
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;
import com.sun.media.jfxmedia.track.Track;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.text.NumberFormat;
import java.util.Locale;

public class Main {
    public static void main(String[] args) throws Exception {
        System.exit(main_ret(args));
    }

    private static int printHelp() {
        System.out.println("Usage:");
        System.out.println("    { -enc  | -dec } { asc | hex | file }");
        System.out.println("    { DES | 3DES | AES }");
        System.out.println("    { ECB | CBC <iv> | CTR <nonce> } -key <key>");
        System.out.println("    [input ascii/hex/file] [output file]");
        System.out.println("");
        System.out.println("For example:");
        System.out.println("    -enc hex DES ECB -key 853f31351e51cd9c ff00");
        System.out.println("");
        System.out.println("Input hex or file is necessary in hex/file modes.");
        System.out.println("Output file is necessary in file mode.");
        return 2;
    }

    private static int printHelp(String emsg) {
        System.out.println(emsg);
        return printHelp();
    }
    
    public static int main_ret(String[] args) throws IOException {
        if (args.length < 1)
            return printHelp();
        
        OperationMode om = parseParameters(args, 0);
        if (om == null)
            return printHelp("Illegal syntax");
        
        IBlockCipher bc = om.getCipher();
        IBlockMode bm = om.getBlockMode(bc);
        InputStream is = null;
        OutputStream os = null;
        
        byte[] key = om.getKey();
        byte[] iv = om.getIV();
        
        if (key == null) {
            return printHelp("Invalid hex given for key");
        }
        if (iv == null) {
            return printHelp("Invalid hex given for IV");
        }
        
        if (key.length == 7 && om.getCipherType() == OperationMode.Cipher.DES) {
            // expand key
            key = Utils.prepareDESKey(key);
        }
        if (key.length == 21 && om.getCipherType() == OperationMode.Cipher.TDES) {
            // expand key
            key = Utils.prepare3DESKey(key);
        }
        if (!bc.isValidKeySize(key.length)) {
            return printHelp(String.format("Invalid key size (%db) for cipher",
                                           8 * key.length));
        }
        if (!bm.isValidIVSize(iv.length)) {
            return printHelp(String.format("Invalid IV size (%db) for cipher",
                                           8 * iv.length));
        }
        
        switch (om.getIOMode()) {
        case ASCII: {
            if (om.getInputString().isEmpty()) {
                is = System.in;
            } else {
                PipedOutputStream pout = new PipedOutputStream();
                is = new PipedInputStream(pout);
                pout.write(om.getInputString().getBytes("ISO-8859-1"));
                pout.close();
            }
            os = System.out;
            break;
        }
        case HEX: {
            byte[] chex = Utils.convertToHex(om.getInputString());
            if (chex == null) {
                return printHelp("Invalid hex given for input");
            }

            PipedOutputStream pout = new PipedOutputStream();
            is = new PipedInputStream(pout);
            pout.write(chex);
            pout.close();
            os = new HexOutputStream(System.out);
            break;
        }
        case FILE: {
            is = new FileInputStream(om.getInputString());
            if (new File(om.getOutputString()).exists()) {
                if (!Utils.confirmPrompt("Overwrite output file")) {
                    return 2;
                }
            }
            os = new FileOutputStream(om.getOutputString());
        }
        }
        
        byte[] block;
            
        long usedMemoryBefore = Runtime.getRuntime().totalMemory()
                              - Runtime.getRuntime().freeMemory();
        long nanoTimeBefore   = System.nanoTime();
            
        if (om.getDirection() == OperationMode.Direction.ENCRYPT) {
            StreamBlockReader sbr = new StreamBlockReader(is, bc.getBlockSizeInBytes());
            bc.initEncrypt(key);
            bm.initEncrypt(iv);
            
            while ((block = sbr.nextBlock()) != null) {
                os.write(bm.process(block));
                os.flush();
            }
            
            bm.finish();
            bc.finish();
        } else if (om.getDirection() == OperationMode.Direction.DECRYPT) {
            StreamBlockReader sbr = new StreamBlockReader(is, bc.getBlockSizeInBytes(), false);
            PaddingRemoverWriter prw = new PaddingRemoverWriter(os, bc.getBlockSizeInBytes());
            
            bc.initDecrypt(key);
            bm.initDecrypt(iv);
            
            while ((block = sbr.nextBlock()) != null) {
                prw.feedBlock(bm.process(block));
            }
            
            prw.finish();
            bm.finish();
            bc.finish();
        }
        
        long nanoTimeAfter    = System.nanoTime();
        long usedMemoryAfter  = Runtime.getRuntime().totalMemory()
                              - Runtime.getRuntime().freeMemory();
        
        if (is != null)
            is.close();
        if (os != null)
            os.close();
        
        System.err.println("=========================================");
        System.err.println(String.format("Time  %30s nsec", NumberFormat
                            .getNumberInstance(Locale.US)
                            .format(nanoTimeAfter - nanoTimeBefore)
                            .replace(',', ' ')));
        System.err.println(String.format("Mem   %30s    B", NumberFormat
                            .getNumberInstance(Locale.US)
                            .format(usedMemoryAfter - usedMemoryBefore)
                            .replace(',', ' ')));
        System.err.println("=========================================");
        
        return 0;
    }

    private static OperationMode parseParameters(String[] args, int start) {
        int i = start;
        
        try {
            OperationMode.Direction dir;
            OperationMode.Cipher ciph;
            OperationMode.BlockMode bm;
            OperationMode.IOMode io;
            String key = "";
            String iv = "";
            String in = "";
            String out = "";
            
            dir = OperationMode.Direction.fromArgument(args[i++]);
            io = OperationMode.IOMode.fromArgument(args[i++]);
            ciph = OperationMode.Cipher.fromArgument(args[i++]);
            bm = OperationMode.BlockMode.fromArgument(args[i++]);
            
            if (dir == null || io == null 
                    || ciph == null || bm == null) return null;
            
            if (bm != OperationMode.BlockMode.ECB) {
                iv = args[i++];
            }
            
            if (!args[i++].equalsIgnoreCase("-key")) {
                System.err.println("no key given");
                return null;
            }
            
            key = args[i++];
            if (io != OperationMode.IOMode.ASCII || i < args.length) {
                in = args[i++];
            }
            if (io == OperationMode.IOMode.FILE) {
                out = args[i++];
            }
            
            return new OperationMode(dir, ciph, bm, io, key, iv, in, out);
        } catch (ArrayIndexOutOfBoundsException ex) {
            return null;
        }
    }
}
