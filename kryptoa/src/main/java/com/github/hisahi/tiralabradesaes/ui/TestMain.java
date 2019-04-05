
package com.github.hisahi.tiralabradesaes.ui; 

import com.github.hisahi.tiralabradesaes.VoidOutputStream;
import com.github.hisahi.tiralabradesaes.Base64OutputStream;
import com.github.hisahi.tiralabradesaes.HexOutputStream;
import com.github.hisahi.tiralabradesaes.PaddingRemoverWriter;
import com.github.hisahi.tiralabradesaes.StreamBlockReader;
import com.github.hisahi.tiralabradesaes.Utils;
import com.github.hisahi.tiralabradesaes.blockmodes.IBlockMode;
import com.github.hisahi.tiralabradesaes.ciphers.IBlockCipher;
import com.github.hisahi.tiralabradesaes.hash.HashSHA2_512;
import com.github.hisahi.tiralabradesaes.keyderiv.HMACFunction;
import com.github.hisahi.tiralabradesaes.keyderiv.IKeyDerivation;
import com.github.hisahi.tiralabradesaes.keyderiv.KeyDerivPBKDF2;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.text.NumberFormat;
import java.util.Arrays;
import java.util.Locale;
import java.util.Scanner;

public class TestMain {
    private static final String HORIZ_SEP =  
            "=======================================================";
    private static boolean overwriteAlways = false;
    private static boolean testMode = false;

    public static void main(String[] args) throws Exception {
        System.exit(main_ret(args));
    }

    private static int printHelp() {
        System.out.println("Usage:");
        System.out.println("    { -enc  | -dec } { asc | hex | b64 | file }");
        System.out.println("    { DES | 3DES | AES }");
        System.out.println("    { ECB | CBC <iv> | CTR <nonce> }");
        System.out.println("    { -key <hex> | -pass <pw> | -kfile <file> }");
        System.out.println("    [input ascii/hex/file] [output file]");
        System.out.println("");
        System.out.println("For example:");
        System.out.println("    -enc hex DES ECB -key 853f31351e51cd9c ff00");
        System.out.println("");
        System.out.println("Input hex, b64 or file is necessary in");
        System.out.println("hex/b64/file modes.");
        System.out.println("Output file is necessary in file mode.");
        System.out.println("");
        System.out.println("Test usage (always for file):");
        System.out.println("    -test <password> <input file");
        return 2;
    }

    private static int printHelp(String emsg) {
        System.out.println(emsg);
        return printHelp();
    }
    
    private static int doMain(OperationMode om) throws IOException {
        IBlockCipher bc = om.getCipher();
        IBlockMode bm = om.getBlockMode(bc);
        InputStream is;
        OutputStream os;
        HMACFunction hmac = new HMACFunction(new HashSHA2_512());
        IKeyDerivation kdf = new KeyDerivPBKDF2(hmac, 1);
        boolean keyIsPassword = false;
        boolean ivInStream = false;
        byte[] pass = null;
        byte[] salt = null;
        
        byte[] block;
            
        long usedMemoryBefore = Runtime.getRuntime().totalMemory()
                              - Runtime.getRuntime().freeMemory();
        long nanoTimeTotal    = 0;
        long nanoTimeKdf      = 0;
        long nanoTimeProcess  = 0;
        long processBytes     = 0;
        
        nanoTimeTotal -= System.nanoTime();
        
        nanoTimeKdf -= System.nanoTime();
        
        byte[] key;
        byte[] iv;
        
        switch (om.getKeyMode()) {
        case HEX:
            key = om.getKeyHex();
            iv = om.getIVHex();
            ivInStream = om.isIVRandom();
            break;
        case PASS:
            pass = om.getKeyPassword();
            switch (om.getCipherType()) {
                case DES:
                    key = new byte[7];
                    break;
                case TDES:
                    key = new byte[21];
                    break;
                case AES:
                    key = new byte[32];
                    break;
                default:
                    key = new byte[0];
                    break;
            }
            salt = new byte[hmac.getBlockSize()];
            keyIsPassword = true;

            iv = new byte[bc.getBlockSizeInBytes()];
            if (om.getDirection() == OperationMode.Direction.ENCRYPT) {
                kdf.calibrateTime(100, 24); // KDF should take 100 ms
                // generate random salt
                Utils.generateStrongRandom(salt);
                // generate key now; for decryption we need the salt and
                // IV values from the stream
                kdf.deriveKey(key, pass, salt);
                // generate random IV for encryption
                Utils.generateStrongRandom(iv);
            }
            break;
        case FILE:
            try {
                is = new BufferedInputStream(new FileInputStream(
                                            om.getKeyString()));

                iv = new byte[bc.getBlockSizeInBytes()];
                if (is.read(iv) < iv.length) {
                    return printHelp("file does not contain valid IV");
                }

                key = new byte[128];
                int keyLen = is.read(key);

                if (keyLen < 1) {
                    return printHelp("file does not contain valid key");
                }
                key = Arrays.copyOf(key, keyLen);
            } catch (FileNotFoundException ex) {
                return printHelp("Invalid hex or filename given for key: "
                                + ex.getMessage());
            }
            break;
        default:
            key = iv = null;
        }
        
        if (key == null) {
            return printHelp("Invalid key given: invalid hex? invalid file?");
        }
        if (!keyIsPassword && !ivInStream && iv == null) {
            return printHelp("IV was not given or invalid hex");
        }
        
        if (ivInStream && iv != null) {
            iv = new byte[bc.getBlockSizeInBytes()];
            Utils.generateStrongRandom(iv);
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
        
        nanoTimeKdf += System.nanoTime();
        
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
            if (om.getOutputString() == null) {
                os = new VoidOutputStream();
            } else {
                os = new BufferedOutputStream(new FileOutputStream(
                                                om.getOutputString()));
            }
            break;
        }
        default:
            return 0;
        }
            
        if (om.getDirection() == OperationMode.Direction.ENCRYPT) {
            StreamBlockReader sbr = new StreamBlockReader(is, 
                                        bc.getBlockSizeInBytes());
            bm.initEncrypt(key, iv);
            
            if (keyIsPassword) {
                // write KDF cost, salt, IV to output stream
                new DataOutputStream(os).writeLong(kdf.getCost());
                os.write(salt);
                os.write(iv);
            } else if (ivInStream) {
                os.write(iv);
            }
            
            while ((block = sbr.nextBlock()) != null) {
                nanoTimeProcess -= System.nanoTime();
                block = bm.process(block);
                nanoTimeProcess += System.nanoTime();
                os.write(block);
                processBytes += block.length;
            }
            
            bm.finish();
        } else if (om.getDirection() == OperationMode.Direction.DECRYPT) {
            if (keyIsPassword) {
                nanoTimeKdf -= System.nanoTime();
                // read KDF cost, salt, IV from stream
                salt = new byte[hmac.getBlockSize()];
                
                kdf.setCost(new DataInputStream(is).readLong());
                is.read(salt);
                is.read(iv);
                
                kdf.deriveKey(key, pass, salt);
                nanoTimeKdf += System.nanoTime();
            } else if (ivInStream) {
                is.read(iv);
            }
            
            StreamBlockReader sbr = new StreamBlockReader(is, 
                                        bc.getBlockSizeInBytes(), false);
            PaddingRemoverWriter prw = new PaddingRemoverWriter(os, 
                                        bc.getBlockSizeInBytes());
            
            bm.initDecrypt(key, iv);
            
            while ((block = sbr.nextBlock()) != null) {
                nanoTimeProcess -= System.nanoTime();
                block = bm.process(block);
                nanoTimeProcess += System.nanoTime();
                processBytes += prw.feedBlock(block);
            }
            
            processBytes += prw.finish();
            bm.finish();
        }
        
        long usedMemoryAfter  = Runtime.getRuntime().totalMemory()
                              - Runtime.getRuntime().freeMemory();
        
        if (is != null)
            is.close();
        if (os != null)
            os.close();
        
        Utils.destroyArray(key);
        Utils.destroyArray(iv);
        if (pass != null)
            Utils.destroyArray(pass);
        if (salt != null)
            Utils.destroyArray(salt);
        
        nanoTimeTotal += System.nanoTime();
        
        // print details
        NumberFormat dnf = NumberFormat.getNumberInstance(Locale.US);
        dnf.setMinimumFractionDigits(3);
        
        System.err.println(HORIZ_SEP);
        System.err.println(String.format("Time            %30s     nsec", 
                NumberFormat.getNumberInstance(Locale.US)
                            .format(nanoTimeTotal)
                            .replace(',', ' ')));
        System.err.println(String.format("Time KDF        %30s     nsec", 
                NumberFormat.getNumberInstance(Locale.US)
                            .format(nanoTimeKdf)
                            .replace(',', ' ')));
        System.err.println(String.format("Time enc/dec    %30s     nsec", 
                NumberFormat.getNumberInstance(Locale.US)
                            .format(nanoTimeProcess)
                            .replace(',', ' ')));
        System.err.println(String.format("Mem             %30s        B", 
                NumberFormat.getNumberInstance(Locale.US)
                            .format(Math.max(0, 
                                    usedMemoryAfter - usedMemoryBefore))
                            .replace(',', ' ')));
        if (!testMode)
            System.err.println(HORIZ_SEP);
        System.err.println(String.format("Processed       %30s        B", 
                NumberFormat.getNumberInstance(Locale.US)
                            .format(processBytes)
                            .replace(',', ' ')));
        System.err.println(String.format("Exec speed      %34s  B/s", 
                            dnf.format((processBytes * 1000) 
                                     / (nanoTimeTotal   * 0.000001))
                            .replace(',', ' ')));
        System.err.println(String.format("Enc/dec speed   %34s  B/s", 
                            dnf.format((processBytes * 1000) 
                                     / (nanoTimeProcess * 0.000001))
                            .replace(',', ' ')));
        if (!testMode)
            System.err.println(HORIZ_SEP);
        else
            System.err.println("");
        
        return 0;
    }
    
    private static int doTestMain(OperationMode base_om) throws IOException {
        int ret = 0;
        overwriteAlways = testMode = true;
        
        for (OperationMode.Cipher ciph: OperationMode.Cipher.values()) {
            for (OperationMode.BlockMode bm: 
                    OperationMode.BlockMode.values()) {
                OperationMode fom = new OperationMode(
                                    OperationMode.Direction.ENCRYPT, 
                                    ciph, 
                                    bm,
                                    OperationMode.IOMode.FILE, 
                                    OperationMode.KeyMode.PASS, 
                                    base_om.getKeyString(), 
                                    "", 
                                    base_om.getInputString(), 
                                    null);
                
                System.err.println(HORIZ_SEP);
                System.err.println(ciph.name() + ", " + bm.name());
                if ((ret = doMain(fom)) != 0) {
                    return ret;
                }
            }
        }
        
        return 0;
    }
    
    public static int main_ret(String[] args) throws IOException {
        if (args.length < 1)
            return printHelp();
        
        OperationMode om = parseParameters(args, 0);
        if (om == null)
            return printHelp("Illegal syntax");
        
        if (om.getDirection() == OperationMode.Direction.TEST)
            return doTestMain(om);
        
        return doMain(om);
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
            OperationMode.KeyMode km;
            String key;
            String iv = "";
            String in = "";
            String out = "";
            
            dir = OperationMode.Direction.fromArgument(args[i++]);
            if (dir == OperationMode.Direction.TEST) {
                key = args[i++];
                in = args[i++];
                return new OperationMode(dir, null, null, null, null,
                                    key, null, in, null);
            }
            
            io = OperationMode.IOMode.fromArgument(args[i++]);
            ciph = OperationMode.Cipher.fromArgument(args[i++]);
            bm = OperationMode.BlockMode.fromArgument(args[i++]);
            
            if (dir == null || io == null 
                    || ciph == null || bm == null) return null;
            
            if (bm != OperationMode.BlockMode.ECB) {
                if (args[i].length() < 2 || !args[i].startsWith("-")) {
                    iv = args[i++];
                }
            }
            
            km = OperationMode.KeyMode.fromArgument(args[i++]);
            if (km == null) {
                System.err.println("invalid key mode");
                return null;
            }
            
            key = args[i++];
            if (io != OperationMode.IOMode.ASCII || i < args.length) {
                in = args[i++];
            }
            if (io == OperationMode.IOMode.FILE) {
                out = args[i++];
            }
            
            return new OperationMode(dir, ciph, bm, io, km, key, iv, in, out);
        } catch (ArrayIndexOutOfBoundsException ex) {
            return null;
        }
    }
}
