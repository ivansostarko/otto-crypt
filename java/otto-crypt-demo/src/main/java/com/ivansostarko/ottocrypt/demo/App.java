package com.ivansostarko.ottocrypt.demo;

import com.ivansostarko.ottocrypt.Otto;
import com.ivansostarko.ottocrypt.OttoResult;

import java.io.File;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public final class App {
    public static void main(String[] args) {
        if (args.length == 0) {
            usage(); return;
        }
        String cmd = args[0];
        Map<String,String> a = parseArgs(args);

        try {
            switch (cmd) {
                case "text": {
                    String keyB64 = opt(a, "--key-b64", System.getenv("OTTO_RAWKEY_B64"));
                    String msg = a.get("--message");
                    if (keyB64 == null || msg == null) throw new IllegalArgumentException("missing --key-b64 or --message");
                    byte[] rawKey = Base64.getDecoder().decode(keyB64);
                    OttoResult enc = Otto.encryptString(msg.getBytes(), rawKey);
                    System.out.println("HEADER_B64=" + Base64.getEncoder().encodeToString(enc.header));
                    System.out.println("CIPHER_B64=" + Base64.getEncoder().encodeToString(enc.cipherAndTag));
                    byte[] dec = Otto.decryptString(enc.cipherAndTag, enc.header, rawKey);
                    System.out.println("DECRYPTED=" + new String(dec));
                    break;
                }
                case "file": {
                    String keyB64 = opt(a, "--key-b64", System.getenv("OTTO_RAWKEY_B64"));
                    String input = a.get("--input");
                    String outEnc = a.get("--out-enc");
                    String outDec = a.get("--out-dec");
                    int chunk = Integer.parseInt(opt(a, "--chunk", Integer.toString(Otto.DEFAULT_CHUNK_SIZE)));
                    if (keyB64 == null || input == null) throw new IllegalArgumentException("missing --key-b64 or --input");
                    if (outEnc == null) outEnc = input + ".otto";
                    if (outDec == null) outDec = input + ".dec";
                    byte[] rawKey = Base64.getDecoder().decode(keyB64);
                    System.out.println("Encrypting " + input + " -> " + outEnc);
                    Otto.encryptFile(Path.of(input), Path.of(outEnc), rawKey, chunk);
                    System.out.println("Decrypting " + outEnc + " -> " + outDec);
                    Otto.decryptFile(Path.of(outEnc), Path.of(outDec), rawKey);
                    System.out.println("Done.");
                    break;
                }
                case "batch": {
                    String keyB64 = opt(a, "--key-b64", System.getenv("OTTO_RAWKEY_B64"));
                    String dir = a.get("--dir");
                    String out = a.get("--out");
                    int chunk = Integer.parseInt(opt(a, "--chunk", Integer.toString(Otto.DEFAULT_CHUNK_SIZE)));
                    if (keyB64 == null || dir == null || out == null) throw new IllegalArgumentException("missing --key-b64/--dir/--out");
                    byte[] rawKey = Base64.getDecoder().decode(keyB64);
                    File d = new File(dir);
                    if (!d.exists() || !d.isDirectory()) throw new IllegalArgumentException("--dir is not a directory");
                    for (File f : d.listFiles()) {
                        processRecursive(f, dir, out, rawKey, chunk);
                    }
                    System.out.println("Batch complete. Output: " + out);
                    break;
                }
                default:
                    usage();
            }
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            System.exit(2);
        }
    }

    private static void processRecursive(File f, String baseDir, String outDir, byte[] key, int chunk) throws Exception {
        if (f.isDirectory()) {
            for (File c : f.listFiles()) processRecursive(c, baseDir, outDir, key, chunk);
            return;
        }
        if (f.getName().endsWith(".otto")) return;
        String rel = f.getAbsolutePath().substring(new File(baseDir).getAbsolutePath().length());
        File outSub = new File(outDir, new File(rel).getParent() == null ? "" : new File(rel).getParent());
        outSub.mkdirs();
        String encOut = new File(outSub, f.getName() + ".otto").getPath();
        String decOut = new File(outSub, f.getName() + ".dec").getPath();
        System.out.println("Encrypting " + f + " -> " + encOut);
        Otto.encryptFile(f.toPath(), Path.of(encOut), key, chunk);
        System.out.println("Decrypting " + encOut + " -> " + decOut);
        Otto.decryptFile(Path.of(encOut), Path.of(decOut), key);
    }

    private static Map<String,String> parseArgs(String[] args) {
        Map<String,String> m = new HashMap<>();
        for (int i=1; i<args.length; i++) {
            String k = args[i];
            if (k.startsWith("--")) {
                if (i+1 < args.length && !args[i+1].startsWith("--")) {
                    m.put(k, args[++i]);
                } else {
                    m.put(k, "true");
                }
            }
        }
        return m;
    }

    private static String opt(Map<String,String> m, String key, String fallback) {
        return m.containsKey(key) ? m.get(key) : fallback;
    }

    private static void usage() {
        System.out.println("otto-demo (Java)");
        System.out.println("USAGE:");
        System.out.println("  text  --key-b64 <key> --message <utf8>");
        System.out.println("  file  --key-b64 <key> --input <path> [--out-enc <path>] [--out-dec <path>] [--chunk <bytes>]");
        System.out.println("  batch --key-b64 <key> --dir <dir> --out <dir> [--chunk <bytes>]");
    }
}
