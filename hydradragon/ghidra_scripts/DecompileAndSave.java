//@file DecompileAndSave.java
//@brief Ghidra script to decompile all functions in a program and save the
//       C code, P-code, and assembly to a single text file with string extraction
//       and deobfuscation. If file > 10MB only C analysis is performed.
//@author
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.framework.model.DomainFile;

import java.io.PrintWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.Normalizer;
import java.util.Iterator;
import java.util.List;
import java.util.ArrayList;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.nio.charset.StandardCharsets;

public class DecompileAndSave extends GhidraScript {

    // Regex pattern for C string literals
    private static final Pattern C_STRING_PATTERN = Pattern.compile(
        "char\\s+\\*?\\s*[\\w\\d_]+\\[?.*?\\]?\\s*=\\s*\"(.*?)\";",
        Pattern.DOTALL
    );

    // Additional patterns for obfuscated strings
    private static final Pattern HEX_STRING_PATTERN = Pattern.compile(
        "\\\\x([0-9a-fA-F]{2})"
    );

    private static final Pattern OCTAL_STRING_PATTERN = Pattern.compile(
        "\\\\([0-7]{1,3})"
    );

    // Deobfuscation thresholds
    private static final int MIN_XOR_LENGTH = 6;                // don't try XOR on very short strings
    private static final double MIN_PRINTABLE_RATIO_XOR = 0.90; // require high printable ratio for XOR results

    // File-size threshold: 10 MB
    private static final long LARGE_FILE_THRESHOLD = 10L * 1024L * 1024L;

    @Override
    protected void run() throws Exception {
        decompileAndSave();
    }

    /**
     * Iterates through all functions in the current program, decompiles them,
     * extracts C code, performs string extraction and deobfuscation. For files
     * larger than LARGE_FILE_THRESHOLD only C analysis is performed.
     */
    private void decompileAndSave() {
        Program program = currentProgram;
        if (program == null) {
            println("Error: No program is currently loaded.");
            return;
        }

        // Determine program file size (best-effort). Use DomainFile if available, otherwise
        // fall back to summing memory block sizes.
        long programSize = -1;
        try {
            DomainFile df = program.getDomainFile();
            if (df != null) {
                programSize = df.getLength();
            }
        } catch (Exception e) {
            // ignore and fallback below
        }

        if (programSize < 0) {
            // Fallback: sum memory block sizes
            try {
                programSize = 0;
                for (MemoryBlock block : program.getMemory().getBlocks()) {
                    if (block.isInitialized() && !block.isOverlay()) {
                        programSize += block.getSize();
                    }
                }
            } catch (Exception e) {
                // If we still can't determine, set -1 to indicate unknown
                programSize = -1;
            }
        }

        boolean largeFile = (programSize > 0) && (programSize > LARGE_FILE_THRESHOLD);
        boolean doFullAnalysis = !largeFile;

        // Setup decompiler
        DecompileOptions options = new DecompileOptions();
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(options);
        decompiler.openProgram(program);

        // Setup output
        String programName = program.getName();
        String safeProgramName = sanitizeFileName(programName);

        Path currentDirPath = Paths.get(System.getProperty("user.dir"));
        Path outputDir = currentDirPath.resolve("decompiled");

        try {
            if (!Files.exists(outputDir)) {
                Files.createDirectories(outputDir);
                println("Output directory created at: " + outputDir.toString());
            }
        } catch (IOException e) {
            println("Error creating directory: " + e.getMessage());
            return;
        }

        // Single consolidated output file
        Path outputFilePath = getUniqueFilePath(outputDir, safeProgramName + "_analysis", ".txt");

        println("Original program name: " + programName);
        println("Sanitized filename base: " + safeProgramName);
        if (programSize > 0) {
            println(String.format("Detected program size: %d bytes (%.2f MB)", programSize, programSize / (1024.0 * 1024.0)));
        } else {
            println("Detected program size: unknown");
        }

        if (largeFile) {
            println("Program exceeds " + (LARGE_FILE_THRESHOLD / (1024 * 1024)) + " MB — only performing C (decompiled) analysis.");
        } else {
            println("Performing full analysis (C, P-Code, Assembly, and memory/data scans).");
        }
        println("Saving consolidated output to: " + outputFilePath.toString());

        // --- Process Functions ---
        Listing listing = program.getListing();
        FunctionManager functionManager = program.getFunctionManager();
        int functionCount = 0;

        // Keep a list of all extracted strings in discovery order (do NOT dedupe)
        List<ExtractedString> allRawStrings = new ArrayList<>();
        Set<String> uniqueDeobfuscated = new HashSet<>();

        // Process all functions and write everything to one file
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFilePath.toFile()))) {

            // Top-level header
            writer.println("Analysis for program: " + programName);
            writer.println("================================================================================");
            writer.println();
            if (programSize > 0) {
                writer.println(String.format("Program size: %d bytes (%.2f MB)", programSize, programSize / (1024.0 * 1024.0)));
            } else {
                writer.println("Program size: unknown");
            }
            writer.println("Analysis mode: " + (doFullAnalysis ? "FULL" : "C_ONLY (skipping P-Code, Assembly, and memory/data scans)"));
            writer.println();

            Iterator<Function> functionIterator = functionManager.getFunctions(true);
            while (functionIterator.hasNext()) {
                Function func = functionIterator.next();
                functionCount++;
                println("Processing function: " + func.getName());

                writer.println("----- Function: " + func.getName() + " @ " + func.getEntryPoint() + " -----");

                // Decompile
                DecompileResults results = decompiler.decompileFunction(func, 60, monitor);
                writer.println();
                writer.println("[ C Code ]");

                String decompiledCode = "";
                if (results.decompileCompleted()) {
                    if (results.getDecompiledFunction() != null) {
                        decompiledCode = results.getDecompiledFunction().getC();
                        // user requested no truncation: write full decompiled output
                        writer.println(decompiledCode);
                    } else {
                        writer.println("Could not retrieve decompiled function.");
                    }
                } else {
                    writer.println("Decompilation failed: " + results.getErrorMessage());
                }

                // Extract strings from decompiled C code (keep duplicates and order)
                if (!decompiledCode.isEmpty()) {
                    List<ExtractedString> functionStrings = extractStringsFromC(decompiledCode, func.getName());

                    if (!functionStrings.isEmpty()) {
                        // append to global list preserving discovery order
                        allRawStrings.addAll(functionStrings);

                        writer.println();
                        writer.println("=== EXTRACTED C STRINGS (Function: " + func.getName() + ") ===");
                        for (int i = 0; i < functionStrings.size(); i++) {
                            ExtractedString str = functionStrings.get(i);
                            writer.printf("%4d: %s%n", i + 1, repr(str.rawString));
                        }

                        // Deobfuscate and write processed results inline
                        List<ExtractedString> deobfuscated = deobfuscateStrings(functionStrings);
                        if (!deobfuscated.isEmpty()) {
                            writer.println();
                            writer.println("=== DEOBFUSCATED STRINGS (Function: " + func.getName() + ") ===");
                            for (int i = 0; i < deobfuscated.size(); i++) {
                                ExtractedString str = deobfuscated.get(i);
                                String dedupeKey = str.encoding + "|" + str.processedString;
                                if (uniqueDeobfuscated.add(dedupeKey)) {
                                    writer.printf("%4d: Raw: %s%n", i + 1, repr(str.rawString));
                                    writer.printf("      Processed: %s%n", repr(str.processedString));
                                    writer.printf("      Encoding: %s%n", str.encoding);
                                    writer.println();
                                }
                            }
                        }
                    }
                }

                if (doFullAnalysis) {
                    // 2. Extract P-Code
                    writer.println();
                    writer.println("[ P-Code ]");

                    HighFunction highFunction = results.getHighFunction();
                    if (highFunction != null) {
                        Iterator<PcodeOpAST> pcodeIterator = highFunction.getPcodeOps();
                        while (pcodeIterator.hasNext()) {
                            PcodeOp pcodeOp = pcodeIterator.next();
                            writer.println(pcodeOp.toString());
                        }
                    } else {
                        writer.println("Could not retrieve P-Code.");
                    }

                    // 3. Extract Native Assembly
                    writer.println();
                    writer.println("[ Assembly ]");

                    InstructionIterator instructions = listing.getInstructions(func.getBody(), true);
                    while (instructions.hasNext()) {
                        Instruction instruction = instructions.next();
                        writer.println(instruction.getAddress() + ": " + instruction.toString());
                    }
                } else {
                    // Indicate that detailed analysis was skipped for large files
                    writer.println();
                    writer.println("[ P-Code ]");
                    writer.println("SKIPPED (large file) - only C decompilation performed.");
                    writer.println();
                    writer.println("[ Assembly ]");
                    writer.println("SKIPPED (large file) - only C decompilation performed.");
                }

                writer.println();
                writer.println("================================================================================");
                writer.println();
            }

            if (doFullAnalysis) {
                // === EXTRA PASS 1: Extract defined data strings ===
                Listing listingAll = program.getListing();
                for (Data data : listingAll.getDefinedData(true)) {
                    if (data.getDataType() != null &&
                        data.getDataType().getName().toLowerCase().contains("string")) {
                        try {
                            String val = data.getValue().toString();
                            allRawStrings.add(new ExtractedString(val, val, "DEFINED", "<data>"));
                        } catch (Exception e) {
                            // ignore bad conversions
                        }
                    }
                }

                // === EXTRA PASS 2: Scan memory for raw ASCII sequences ===
                Memory mem = program.getMemory();
                for (MemoryBlock block : mem.getBlocks()) {
                    if (!block.isInitialized() || block.isOverlay()) continue;
                    try {
                        byte[] bytes = new byte[(int) block.getSize()];
                        block.getBytes(block.getStart(), bytes);

                        int start = -1;
                        for (int i = 0; i < bytes.length; i++) {
                            int b = bytes[i] & 0xff;
                            if (b >= 0x20 && b <= 0x7e) { // printable ASCII
                                if (start == -1) start = i;
                            } else {
                                if (start != -1 && i - start >= 4) { // min length = 4
                                    String s = new String(bytes, start, i - start, StandardCharsets.US_ASCII);
                                    allRawStrings.add(new ExtractedString(s, s, "RAW_ASCII", "<memory>"));
                                }
                                start = -1;
                            }
                        }
                    } catch (Exception e) {
                        println("Error scanning block: " + block.getName() + " - " + e.getMessage());
                    }
                }
            } else {
                // For C-only mode we skip data/memory scanning; but log that we skipped it
                writer.println();
                writer.println("=== NOTE ===");
                writer.println("Defined-data string extraction and raw-memory scan SKIPPED due to large program size.");
                writer.println();
            }

            // === FINAL CONSOLIDATED OUTPUT ===
            writer.println();
            writer.println("=== EXTRACTED STRINGS ===");
            for (int i = 0; i < allRawStrings.size(); i++) {
                ExtractedString s = allRawStrings.get(i);
                // print processedString (unescaped) using repr to show escapes like \n
                writer.printf("%4d: %s%n", i + 1, repr(s.processedString));
            }

            // Summary
            writer.println();
            writer.println("=== SUMMARY ===");
            writer.println("Functions processed: " + functionCount);
            writer.println("Total raw strings extracted: " + allRawStrings.size());
            writer.println("Total unique deobfuscated strings: " + uniqueDeobfuscated.size());
            writer.println("Analysis mode: " + (doFullAnalysis ? "FULL" : "C_ONLY"));

        } catch (IOException e) {
            println("Error writing to output file: " + e.getMessage());
            return;
        } finally {
            decompiler.dispose();
        }

        println();
        println("Analysis complete.");
        println("Processed " + functionCount + " functions.");
        println("Extracted " + allRawStrings.size() + " raw strings.");
        println("Deobfuscated " + uniqueDeobfuscated.size() + " unique strings.");
        println("Analysis mode: " + (doFullAnalysis ? "FULL" : "C_ONLY"));
        println("Results saved to: " + outputFilePath.toString());
    }

    /**
     * Extract C string literals from decompiled code
     * This implementation mimics Python's ast.literal_eval unescaping behaviour
     * for common escape sequences so results match the Python extractor.
     */
    private List<ExtractedString> extractStringsFromC(String content, String functionName) {
        List<ExtractedString> extractedStrings = new ArrayList<>();
        Matcher matcher = C_STRING_PATTERN.matcher(content);

        while (matcher.find()) {
            String rawMatch = matcher.group(1);
            try {
                // Process escape sequences into a "logical" string; but DO NOT insert
                // an actual NUL character. Instead represent any parsed NUL as the
                // printable token "0x00" so downstream tools that expect a readable
                // escape won't be broken by embedded NULs.
                String processed = unescapeCString(rawMatch);
                extractedStrings.add(new ExtractedString(rawMatch, processed, "C_STRING", functionName));
            } catch (Exception e) {
                // Fall back to raw match if processing fails
                extractedStrings.add(new ExtractedString(rawMatch, rawMatch, "RAW", functionName));
            }
        }

        return extractedStrings;
    }

    /**
     * Unescape a C-style string literal value into a Java string.
     * - Recognizes: \\n \\r \\t \\b \\f \\\\ \\\" \\' 
     *               \\xHH (hex)
     *               \\uHHHH (unicode)
     *               \\NNN (octal up to 3 digits)
     * - Any parsed NUL (0x00) is represented in the returned string as the
     *   literal characters: 0x00 (so the string never contains an actual NUL).
     */
    private String unescapeCString(String s) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        int len = s.length();
        while (i < len) {
            char c = s.charAt(i);
            if (c != '\\') {
                out.append(c);
                i++;
                continue;
            }
            // escape sequence
            i++;
            if (i >= len) {
                out.append('\\');
                break;
            }
            char esc = s.charAt(i);
            i++;
            switch (esc) {
                case 'n': out.append('\n'); break;
                case 'r': out.append('\r'); break;
                case 't': out.append('\t'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case '\\': out.append('\\'); break;
                case '\'': out.append('\''); break;
                case '\"': out.append('\"'); break;
                case '0':
                    // exact \0 (NUL) -> append printable token "0x00" rather than an actual NUL
                    out.append("0x00");
                    break;
                case 'x':
                case 'X': {
                    // parse 1-2 hex digits (be lenient)
                    int val = 0;
                    int digits = 0;
                    while (i < len && digits < 2) {
                        char h = s.charAt(i);
                        int d = Character.digit(h, 16);
                        if (d == -1) break;
                        val = (val << 4) + d;
                        i++; digits++;
                    }
                    if (digits == 0) {
                        // invalid, keep literal
                        out.append("\\x");
                    } else {
                        if (val == 0) {
                            out.append("0x00");
                        } else {
                            out.append((char) val);
                        }
                    }
                    break;
                }
                case 'u': {
                    // uHHHH (expect exactly 4 hex digits)
                    int val = 0;
                    int start = i;
                    int count = 0;
                    while (i < len && count < 4) {
                        char h = s.charAt(i);
                        int d = Character.digit(h, 16);
                        if (d == -1) break;
                        val = (val << 4) + d;
                        i++; count++;
                    }
                    if (count == 4) {
                        if (val == 0) out.append("0x00"); else out.append((char) val);
                    } else {
                        // invalid sequence -> emit literal
                        out.append("\\u");
                        i = start; // roll back to allow rest to be appended literally
                    }
                    break;
                }
                default: {
                    // maybe octal sequence: up to 3 octal digits including this one (esc)
                    if (esc >= '0' && esc <= '7') {
                        int val = esc - '0';
                        int count = 1;
                        while (i < len && count < 3) {
                            char h = s.charAt(i);
                            if (h < '0' || h > '7') break;
                            val = val * 8 + (h - '0');
                            i++; count++;
                        }
                        if (val == 0) out.append("0x00"); else out.append((char) val);
                    } else {
                        // unknown escape, keep as-is (backslash + char)
                        out.append('\\').append(esc);
                    }
                }
            }
        }
        return out.toString();
    }

    /**
     * Deobfuscate strings using tightened heuristics
     */
    private List<ExtractedString> deobfuscateStrings(List<ExtractedString> inputStrings) {
        List<ExtractedString> deobfuscated = new ArrayList<>();

        for (ExtractedString str : inputStrings) {
            String original = str.processedString;

            // Base64
            String base64Decoded = tryBase64Decode(original);
            if (base64Decoded != null && !base64Decoded.equals(original)) {
                deobfuscated.add(new ExtractedString(str.rawString, base64Decoded, "BASE64", str.functionName));
                continue;
            }

            // Hex
            String hexDecoded = tryHexDecode(original);
            if (hexDecoded != null && !hexDecoded.equals(original)) {
                deobfuscated.add(new ExtractedString(str.rawString, hexDecoded, "HEX", str.functionName));
                continue;
            }

            // ROT
            boolean added = false;
            for (int shift = 1; shift < 26; shift++) {
                String rotDecoded = caesarDecode(original, shift);
                if (isMostlyPrintable(rotDecoded, 0.90) && containsCommonWords(rotDecoded)) {
                    deobfuscated.add(new ExtractedString(str.rawString, rotDecoded, "ROT" + shift, str.functionName));
                    added = true;
                    break;
                }
            }
            if (added) continue;

            // XOR
            if (original.length() >= MIN_XOR_LENGTH) {
                for (int key = 1; key < 256; key++) {
                    String xorDecoded = xorDecode(original, key);
                    if (isMostlyPrintable(xorDecoded, MIN_PRINTABLE_RATIO_XOR) && containsVowel(xorDecoded)) {
                        if (xorDecoded.contains(" ") || containsCommonWords(xorDecoded)) {
                            deobfuscated.add(new ExtractedString(str.rawString, xorDecoded, "XOR_" + key, str.functionName));
                            added = true;
                            break;
                        }
                    }
                }
            }
            if (added) continue;

            // If no deobfuscation worked, keep the original
            deobfuscated.add(str);
        }

        return deobfuscated;
    }

    private boolean containsVowel(String s) {
        if (s == null) return false;
        String lower = s.toLowerCase();
        return lower.indexOf('a') >= 0 || lower.indexOf('e') >= 0 || lower.indexOf('i') >= 0 || lower.indexOf('o') >= 0 || lower.indexOf('u') >= 0;
    }

    private boolean isMostlyPrintable(String text, double threshold) {
        if (text == null || text.length() == 0) return false;
        int printableCount = 0;
        for (char c : text.toCharArray()) {
            if (c >= 32 && c <= 126) printableCount++;
        }
        return (double) printableCount / text.length() >= threshold;
    }

    private String tryBase64Decode(String input) {
        try {
            if (input.length() % 4 == 0 && input.matches("[A-Za-z0-9+/=]+")) {
                byte[] decoded = Base64.getDecoder().decode(input);
                String result = new String(decoded, StandardCharsets.UTF_8);
                if (isMostlyPrintable(result, 0.90)) {
                    return result;
                }
            }
        } catch (Exception e) {
            // Ignore decode failures
        }
        return null;
    }

    /**
     * Try to decode hex string
     */
    private String tryHexDecode(String input) {
        try {
            if (input.matches("^[0-9a-fA-F]+$") && input.length() % 2 == 0) {
                StringBuilder result = new StringBuilder();
                for (int i = 0; i < input.length(); i += 2) {
                    String hex = input.substring(i, i + 2);
                    int value = Integer.parseInt(hex, 16);
                    result.append((char) value);
                }
                String decoded = result.toString();
                if (isMostlyPrintable(decoded, 0.90)) {
                    return decoded;
                }
            }
        } catch (Exception e) {
            // Ignore decode failures
        }
        return null;
    }

    /**
     * Caesar cipher decoding
     */
    private String caesarDecode(String input, int shift) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isLetter(c)) {
                char base = Character.isUpperCase(c) ? 'A' : 'a';
                result.append((char) ((c - base - shift + 26) % 26 + base));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * XOR decoding with single byte key
     */
    private String xorDecode(String input, int key) {
        StringBuilder result = new StringBuilder();
        for (char c : input.toCharArray()) {
            result.append((char) (c ^ key));
        }
        return result.toString();
    }

    /**
     * Check if string contains mostly printable characters
     */
    private boolean isPrintableText(String text) {
        if (text == null || text.length() == 0) return false;

        int printableCount = 0;
        for (char c : text.toCharArray()) {
            if (c >= 32 && c <= 126) printableCount++;
        }
        return (double) printableCount / text.length() > 0.75;
    }

    /**
     * Check if string contains common English words (simple heuristic)
     */
    private boolean containsCommonWords(String text) {
        if (text == null) return false;
        String lower = text.toLowerCase();
        String[] commonWords = {"the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "her", "was", "one", "our", "out", "day", "get", "has", "him", "his", "how", "its", "may", "new", "now", "old", "see", "two", "way", "who", "boy", "did", "man", "run", "too"};

        for (String word : commonWords) {
            if (lower.contains(word)) return true;
        }
        return false;
    }

    /**
     * Java equivalent of Python's repr() function
     */
    private String repr(String input) {
        if (input == null) return "null";

        StringBuilder result = new StringBuilder("'");
        for (char c : input.toCharArray()) {
            switch (c) {
                case '\n': result.append("\\n"); break;
                case '\t': result.append("\\t"); break;
                case '\r': result.append("\\r"); break;
                case '\\': result.append("\\\\"); break;
                case '\'': result.append("\\'"); break;
                default:
                    if (c == 0) {
                        // represent NUL as 0x00 (printable token)
                        result.append("0x00");
                    } else if (c >= 32 && c <= 126) {
                        result.append(c);
                    } else {
                        result.append(String.format("\\x%02x", (int) c));
                    }
            }
        }
        result.append("'");
        return result.toString();
    }

    /**
     * Helper method to create unique filenames
     */
    private Path getUniqueFilePath(Path outputDir, String baseFileName, String fileExtension) {
        Path filePath = outputDir.resolve(baseFileName + fileExtension);
        int fileIndex = 1;

        while (Files.exists(filePath)) {
            filePath = outputDir.resolve(baseFileName + "_" + fileIndex + fileExtension);
            fileIndex++;
        }

        return filePath;
    }

    /**
     * Sanitize a string so it can safely be used as a filename on common filesystems.
     * Replaces reserved/invalid characters, removes control characters, trims trailing
     * dots/spaces (Windows), and enforces a reasonable max length.
     */
    private String sanitizeFileName(String name) {
        if (name == null) return "program";

        // Normalize unicode to decompose accents, then remove non-ASCII where possible
        String normalized = Normalizer.normalize(name, Normalizer.Form.NFKD);

        // Replace filesystem reserved characters with underscores
        String replaced = normalized.replaceAll("[\\\\/:*?\"<>|]", "_");

        // Remove control characters
        replaced = replaced.replaceAll("\\p{Cntrl}+", "");

        // Trim whitespace
        replaced = replaced.trim();

        // Windows doesn't allow filenames ending with dot or space
        while (replaced.endsWith(".") || replaced.endsWith(" ")) {
            replaced = replaced.substring(0, replaced.length() - 1);
        }

        // Collapse runs of underscores
        replaced = replaced.replaceAll("_+", "_");

        // If empty after sanitization, use a safe fallback
        if (replaced.isEmpty()) replaced = "program";

        // Enforce a maximum length to avoid path length issues
        int maxLen = 200;
        if (replaced.length() > maxLen) {
            replaced = replaced.substring(0, maxLen);
        }

        return replaced;
    }

    /**
     * Helper class to store extracted string information
     */
    private static class ExtractedString {
        public final String rawString;
        public final String processedString;
        public final String encoding;
        public final String functionName;

        public ExtractedString(String rawString, String processedString, String encoding, String functionName) {
            this.rawString = rawString;
            this.processedString = processedString;
            this.encoding = encoding;
            this.functionName = functionName;
        }
    }
}
