
package com.github.hisahi.tiralabradesaes.ui; 

import com.github.hisahi.tiralabradesaes.Base64OutputStream;
import com.github.hisahi.tiralabradesaes.HexOutputStream;
import com.github.hisahi.tiralabradesaes.PaddingRemoverWriter;
import com.github.hisahi.tiralabradesaes.StreamBlockReader;
import com.github.hisahi.tiralabradesaes.Utils;
import com.github.hisahi.tiralabradesaes.blockmodes.IBlockMode;
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
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
import java.util.Scanner;

public class Main {
    private static boolean overwriteAlways = false;
    
    public static void main(String[] args) throws Exception {
        System.exit(main_ret(args));
    }

    private static int printHelp() {
        System.out.println("Usage:");
        System.out.println("    { -enc  | -dec } { asc | hex | b64 | file }");
        System.out.println("    { DES | 3DES | AES }");
        System.out.println("    { ECB | CBC <iv> | CTR <nonce> } -key <key>");
        System.out.println("    [input ascii/hex/file] [output file]");
        System.out.println("");
        System.out.println("For example:");
        System.out.println("    -enc hex DES ECB -key 853f31351e51cd9c ff00");
        System.out.println("");
        System.out.println("Input hex, b64 or file is necessary in");
        System.out.println("hex/b64/file modes.");
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
        
        if (key.length == 7 
                        && om.getCipherType() == OperationMode.Cipher.DES) {
            // expand key
            key = Utils.prepareDESKey(key);
        } else if (key.length == 14 
                        && om.getCipherType() == OperationMode.Cipher.TDES) {
            // expand key
            key = Utils.prepare3DESKeyFrom14Bytes(key);
        } else if (key.length == 16 
                        && om.getCipherType() == OperationMode.Cipher.TDES) {
            // expand key
            key = Utils.prepare3DESKeyFrom16Bytes(key);
        } else if (key.length == 21 
                        && om.getCipherType() == OperationMode.Cipher.TDES) {
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
            byte[] chex = Utils.convertHexToBytes(om.getInputString());
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
        case BASE64: {
            byte[] chex = Utils.convertBase64ToBytes(om.getInputString());
            if (chex == null) {
                return printHelp("Invalid base64 given for input");
            }

            PipedOutputStream pout = new PipedOutputStream();
            is = new PipedInputStream(pout);
            pout.write(chex);
            pout.close();
            os = new Base64OutputStream(System.out);
            break;
        }
        case FILE: {
            is = new BufferedInputStream(new FileInputStream(
                                            om.getInputString()));
            if (!overwriteAlways && new File(om.getOutputString()).exists()) {
                if (!confirmPrompt("Overwrite output file")) {
                    return 2;
                }
            }
            os = new BufferedOutputStream(new FileOutputStream(
                                            om.getOutputString()));
        }
        }
        
        byte[] block;
            
        long usedMemoryBefore = Runtime.getRuntime().totalMemory()
                              - Runtime.getRuntime().freeMemory();
        long nanoTimeBefore   = System.nanoTime();
        long nanoTimeProcess  = 0;
        long processBytes     = 0;
            
        if (om.getDirection() == OperationMode.Direction.ENCRYPT) {
            StreamBlockReader sbr = new StreamBlockReader(is, 
                                        bc.getBlockSizeInBytes());
            bc.initEncrypt(key);
            bm.initEncrypt(iv);
            
            while ((block = sbr.nextBlock()) != null) {
                nanoTimeProcess -= System.nanoTime();
                block = bm.process(block);
                nanoTimeProcess += System.nanoTime();
                os.write(block);
                processBytes += block.length;
            }
            
            bm.finish();
            bc.finish();
        } else if (om.getDirection() == OperationMode.Direction.DECRYPT) {
            StreamBlockReader sbr = new StreamBlockReader(is, 
                                        bc.getBlockSizeInBytes(), false);
            PaddingRemoverWriter prw = new PaddingRemoverWriter(os, 
                                        bc.getBlockSizeInBytes());
            
            bc.initDecrypt(key);
            bm.initDecrypt(iv);
            
            while ((block = sbr.nextBlock()) != null) {
                nanoTimeProcess -= System.nanoTime();
                block = bm.process(block);
                nanoTimeProcess += System.nanoTime();
                processBytes += prw.feedBlock(block);
            }
            
            processBytes += prw.finish();
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
        
        // print details
        NumberFormat dnf = NumberFormat.getNumberInstance(Locale.US);
        dnf.setMinimumFractionDigits(3);
        
        System.err.println("=======================================================");
        System.err.println(String.format("Time            %30s     nsec", NumberFormat
                            .getNumberInstance(Locale.US)
                            .format(nanoTimeAfter - nanoTimeBefore)
                            .replace(',', ' ')));
        System.err.println(String.format("Time enc/dec    %30s     nsec", NumberFormat
                            .getNumberInstance(Locale.US)
                            .format(nanoTimeProcess)
                            .replace(',', ' ')));
        System.err.println(String.format("Mem             %30s        B", NumberFormat
                            .getNumberInstance(Locale.US)
                            .format(usedMemoryAfter - usedMemoryBefore)
                            .replace(',', ' ')));
        System.err.println("=======================================================");
        System.err.println(String.format("Processed       %30s        B", NumberFormat
                            .getNumberInstance(Locale.US)
                            .format(processBytes)
                            .replace(',', ' ')));
        System.err.println(String.format("Exec speed      %34s  B/s", 
                            dnf.format((processBytes * 1000) / ((nanoTimeAfter - nanoTimeBefore) * 0.000_001))
                            .replace(',', ' ')));
        System.err.println(String.format("Enc/dec speed   %34s  B/s", 
                            dnf.format((processBytes * 1000) / (nanoTimeProcess * 0.000_001))
                            .replace(',', ' ')));
        System.err.println("=======================================================");
        
        return 0;
    }

    public static boolean confirmPrompt(String msg) {
        Scanner keyb = new Scanner(System.in);
        String token;
        String choice = "x";
        
        do {
            System.out.print(msg + " [Y/N]?");
            System.out.flush();
            
            token = keyb.next();
            if (!token.isEmpty()) {
                choice = token.toUpperCase().substring(0, 1);
            }
            
            System.out.println();
        } while (!"YN".contains(choice));
        
        return choice.equalsIgnoreCase("Y");
    }

    private static OperationMode parseParameters(String[] args, int start) {
        int i = start;
        
        try {
            OperationMode.Direction dir;
            OperationMode.Cipher ciph;
            OperationMode.BlockMode bm;
            OperationMode.IOMode io;
            String key;
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
