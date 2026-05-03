//@file DecompileAndSave.java
//@brief Ghidra script to decompile all functions in a program and save the
//       C code, P-code, and assembly to a single text file with string extraction
//       and deobfuscation. If file > 10MB only C analysis is performed.
//@author Emirhan Ucan
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DecompileAndSave extends GhidraScript {

    private boolean debugMode = false;
    private final List<XorKey> dynamicXorKeys = new ArrayList<>();

    private static final long LARGE_FILE_THRESHOLD = 10L * 1024L * 1024L;

    private static final int MIN_XOR_INPUT_LENGTH = 4;
    private static final int MAX_CANDIDATE_BYTES = 192;
    private static final int MAX_FINDINGS_PER_FUNCTION = 400;
    private static final int MAX_STRING_XOR_FINDINGS = 800;
    private static final int MAX_MEMORY_XOR_FINDINGS = 600;
    private static final int MAX_RAW_ASCII_STRINGS = 5000;
    private static final int MAX_MEMORY_BLOCK_SCAN_BYTES = 2 * 1024 * 1024;
    private static final int MAX_TOTAL_MEMORY_SCAN_BYTES = 8 * 1024 * 1024;

    // All quoted literals from decompiled C. This is broader than only char* assignments.
    private static final Pattern C_LITERAL_PATTERN = Pattern.compile("\\\"((?:\\\\.|[^\\\"\\\\])*)\\\"");

    // Hex immediates from decompiled C, including suffixes such as uLL / LL / U.
    // These are treated only as byte candidates. The only decoding step is XOR brute force.
    private static final Pattern HEX_LITERAL_PATTERN = Pattern.compile(
        "(?i)\\b0x([0-9a-f]{2,32})(?:u?ll|ull|ll|ul|u|l)?\\b"
    );

    // Typical decompiler symbol names that embed a static address.
    private static final Pattern ADDRESS_SYMBOL_PATTERN = Pattern.compile(
        "\\b(byte|word|dword|qword|xmmword|ymmword|unk|DAT|PTR)_([0-9a-fA-F]{6,16})\\b"
    );

    private static final Pattern DOMAIN_PATTERN = Pattern.compile(
        "(?i).*[a-z0-9][a-z0-9.-]{1,80}\\.[a-z]{2,10}.*"
    );

    @Override
    protected void run() throws Exception {
        decompileAndSave();
    }

    private void decompileAndSave() {
        Program program = currentProgram;
        if (program == null) {
            println("Error: No program is currently loaded.");
            return;
        }

        debugMode = isDebugModeEnabled();
        dynamicXorKeys.clear();

        long programSize = estimateProgramSize(program);
        boolean largeFile = programSize > LARGE_FILE_THRESHOLD;
        boolean doFullAnalysis = !largeFile;

        String programName = program.getName();
        String safeProgramName = sanitizeFileName(programName);
        Path outputDir = getOutputDir();

        try {
            Files.createDirectories(outputDir);
        } catch (IOException e) {
            println("Error creating output directory: " + e.getMessage());
            return;
        }

        // Keep the original output naming style: <program>_analysis.txt
        Path outputFilePath = getUniqueFilePath(outputDir, safeProgramName + "_analysis", ".txt");

        DecompileOptions options = new DecompileOptions();
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        DecompInterface decompiler = new DecompInterface();
        decompiler.setOptions(options);
        decompiler.openProgram(program);

        FunctionManager functionManager = program.getFunctionManager();
        Listing listing = program.getListing();
        int functionCount = 0;

        List<ExtractedString> allExtractedStrings = new ArrayList<>();
        List<XorFinding> allStringXorFindings = new ArrayList<>();
        List<XorFinding> allXorFindings = new ArrayList<>();
        Set<String> xorDedupe = new LinkedHashSet<>();

        println("Original program name: " + programName);
        println("Sanitized filename base: " + safeProgramName);
        if (programSize >= 0) {
            println(String.format("Detected program size: %d bytes (%.2f MB)", programSize, programSize / (1024.0 * 1024.0)));
        } else {
            println("Detected program size: unknown");
        }
        println("XOR mode: single-byte brute-force plus dynamic symbol keys.");
        println("Saving output to: " + outputFilePath);

        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFilePath.toFile()))) {
            writer.println("// Original file:" + getOriginalFileCommentPath(program));
            writer.println("Analysis for program: " + programName);
            writer.println("================================================================================");
            writer.println();
            if (programSize >= 0) {
                writer.println(String.format("Program size: %d bytes (%.2f MB)", programSize, programSize / (1024.0 * 1024.0)));
            } else {
                writer.println("Program size: unknown");
            }
            writer.println("Analysis mode: " + (doFullAnalysis ? "FULL" : "C_ONLY"));
            writer.println("XOR mode: SINGLE_BYTE_BRUTE_FORCE_PLUS_DYNAMIC_SYMBOL_KEYS");
            writer.println("Tried keys: 0x01 through 0xFF");
            writer.println("Dynamic XOR keys: read from decompiler/Ghidra symbols referenced by the code");
            writer.println("Debug mode: " + (debugMode ? "ON" : "OFF"));
            if (!dynamicXorKeys.isEmpty()) {
                writer.println("Loaded dynamic XOR keys:");
                for (XorKey key : dynamicXorKeys) {
                    writer.printf("  - %s len=%d hex=%s%n", key.name, key.bytes.length, toHex(key.bytes));
                }
            } else {
                writer.println("Loaded dynamic XOR keys: none yet; keys are discovered while functions are decompiled");
            }
            writer.println();

            Iterator<Function> functionIterator = functionManager.getFunctions(true);
            while (functionIterator.hasNext()) {
                Function func = functionIterator.next();
                functionCount++;
                println("Processing function: " + func.getName());

                writer.println("----- Function: " + func.getName() + " @ " + func.getEntryPoint() + " -----");
                writer.println();
                writer.println("[ C Code ]");

                String decompiledCode = "";
                DecompileResults results = decompiler.decompileFunction(func, 60, monitor);
                if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
                    decompiledCode = results.getDecompiledFunction().getC();
                    writer.println(decompiledCode);
                } else {
                    writer.println("Decompilation failed: " + results.getErrorMessage());
                }

                if (!decompiledCode.isEmpty()) {
                    List<XorKey> functionKeys = extractXorKeysFromReferencedSymbols(decompiledCode);
                    if (!functionKeys.isEmpty()) {
                        addUniqueXorKeys(dynamicXorKeys, functionKeys);
                        if (debugMode) {
                            println("Dynamic XOR keys discovered in " + func.getName() + ": " + functionKeys.size());
                        }
                    }

                    List<ExtractedString> functionStrings = extractStringsFromC(decompiledCode, func.getName());
                    allExtractedStrings.addAll(functionStrings);

                    List<XorFinding> stringFindings = deobfuscateExtractedStrings(
                        functionStrings, xorDedupe, MAX_FINDINGS_PER_FUNCTION
                    );
                    allStringXorFindings.addAll(stringFindings);
                    allXorFindings.addAll(stringFindings);

                    List<Candidate> candidates = extractXorCandidatesFromC(decompiledCode, func.getName());
                    List<XorFinding> constantFindings = bruteForceSingleByteXor(candidates, xorDedupe, MAX_FINDINGS_PER_FUNCTION);
                    allXorFindings.addAll(constantFindings);

                    if (!functionStrings.isEmpty()) {
                        writer.println();
                        writer.println("=== EXTRACTED C STRINGS (Function: " + func.getName() + ") ===");
                        for (int i = 0; i < functionStrings.size(); i++) {
                            ExtractedString s = functionStrings.get(i);
                            writer.printf("%4d: %s%n", i + 1, repr(s.processedString));
                        }

                        writer.println();
                        writer.println("=== XOR-DEOBFUSCATED STRINGS ONLY (Function: " + func.getName() + ") ===");
                        writeFindings(writer, stringFindings);
                    }

                    writer.println();
                    writer.println("=== XOR BRUTE-FORCE FINDINGS FROM CONSTANTS/SYMBOL BYTES (Function: " + func.getName() + ") ===");
                    writeFindings(writer, constantFindings);
                }

                if (doFullAnalysis) {
                    writer.println();
                    writer.println("[ Assembly ]");
                    InstructionIterator instructions = listing.getInstructions(func.getBody(), true);
                    while (instructions.hasNext()) {
                        Instruction instruction = instructions.next();
                        writer.println(instruction.getAddress() + ": " + instruction.toString());
                    }
                } else {
                    writer.println();
                    writer.println("[ Assembly ]");
                    writer.println("SKIPPED (large file) - only C decompilation and C-derived XOR brute force performed.");
                }

                writer.println();
                writer.println("================================================================================");
                writer.println();
            }

            if (doFullAnalysis) {
                List<ExtractedString> definedStrings = extractDefinedDataStrings(program);
                allExtractedStrings.addAll(definedStrings);

                List<XorFinding> definedStringFindings = deobfuscateExtractedStrings(
                    definedStrings, xorDedupe, MAX_MEMORY_XOR_FINDINGS
                );
                allStringXorFindings.addAll(definedStringFindings);
                allXorFindings.addAll(definedStringFindings);
                writer.println();
                writer.println("=== XOR-DEOBFUSCATED DEFINED STRINGS ONLY ===");
                writeFindings(writer, definedStringFindings);

                int rawMemoryStartIndex = allExtractedStrings.size();
                addRawAsciiStringsFromMemory(program, allExtractedStrings);
                List<ExtractedString> rawMemoryStrings = new ArrayList<>(
                    allExtractedStrings.subList(rawMemoryStartIndex, allExtractedStrings.size())
                );
                List<XorFinding> rawMemoryStringFindings = deobfuscateExtractedStrings(
                    rawMemoryStrings, xorDedupe, MAX_STRING_XOR_FINDINGS
                );
                allStringXorFindings.addAll(rawMemoryStringFindings);
                allXorFindings.addAll(rawMemoryStringFindings);
                writer.println();
                writer.println("=== XOR-DEOBFUSCATED RAW ASCII MEMORY STRINGS ONLY ===");
                writeFindings(writer, rawMemoryStringFindings);

                List<Candidate> dataCandidates = buildDefinedDataCandidates(program);
                List<XorFinding> dataFindings = bruteForceSingleByteXor(dataCandidates, xorDedupe, MAX_MEMORY_XOR_FINDINGS);
                allXorFindings.addAll(dataFindings);
                writer.println();
                writer.println("=== XOR BRUTE-FORCE FINDINGS FROM DEFINED DATA BYTES ===");
                writeFindings(writer, dataFindings);

                List<XorFinding> memoryFindings = scanMemorySingleByteXor(program.getMemory(), xorDedupe, MAX_MEMORY_XOR_FINDINGS);
                allXorFindings.addAll(memoryFindings);
                writer.println();
                writer.println("=== XOR BRUTE-FORCE FINDINGS FROM MEMORY BLOCKS ===");
                writeFindings(writer, memoryFindings);
            } else {
                writer.println();
                writer.println("=== NOTE ===");
                writer.println("Defined-data strings, raw-memory strings, and memory block XOR scans skipped because the program is larger than 10 MB.");
            }

            writer.println();
            writer.println("=== CONSOLIDATED XOR DEOBFUSCATED STRINGS ===");
            writeFindings(writer, allStringXorFindings);

            writer.println();
            writer.println("=== CONSOLIDATED XOR BRUTE-FORCE FINDINGS ===");
            writeFindings(writer, allXorFindings);

            writer.println();
            writer.println("=== CONSOLIDATED EXTRACTED STRINGS ===");
            for (int i = 0; i < allExtractedStrings.size(); i++) {
                writer.printf("%4d: %s%n", i + 1, repr(allExtractedStrings.get(i).processedString));
            }

            writer.println();
            writer.println("=== ALL DEOBFUSCATED STRINGS (COMBINED COMPLETE LIST) ===");
            writeCombinedDecodedStrings(writer, allXorFindings);

            writer.println();
            writer.println("=== SUMMARY ===");
            writer.println("Functions processed: " + functionCount);
            writer.println("Extracted strings: " + allExtractedStrings.size());
            writer.println("XOR deobfuscated string findings: " + allStringXorFindings.size());
            writer.println("XOR brute-force findings: " + allXorFindings.size());
            writer.println("Output: " + outputFilePath.toString());
        } catch (IOException e) {
            println("Error writing output: " + e.getMessage());
            return;
        } finally {
            decompiler.dispose();
        }

        println();
        println("Analysis complete.");
        println("Processed " + functionCount + " functions.");
        println("XOR brute-force findings: " + allXorFindings.size());
        println("Results saved to: " + outputFilePath);
    }

    private List<ExtractedString> extractStringsFromC(String content, String functionName) {
        List<ExtractedString> out = new ArrayList<>();
        Matcher matcher = C_LITERAL_PATTERN.matcher(content);
        while (matcher.find()) {
            String raw = matcher.group(1);
            String processed;
            try {
                processed = unescapeCString(raw);
            } catch (Exception e) {
                processed = raw;
            }
            out.add(new ExtractedString(raw, processed, "C_STRING", functionName));
        }
        return out;
    }

    private List<Candidate> extractXorCandidatesFromC(String content, String functionName) {
        List<Candidate> candidates = new ArrayList<>();
        List<byte[]> constants = new ArrayList<>();
        List<String> labels = new ArrayList<>();

        Matcher matcher = HEX_LITERAL_PATTERN.matcher(content);
        while (matcher.find()) {
            String hex = matcher.group(1);
            byte[] bytes = littleEndianBytesFromHexLiteral(hex);
            if (bytes.length >= MIN_XOR_INPUT_LENGTH && bytes.length <= MAX_CANDIDATE_BYTES && !isAllSameByte(bytes)) {
                constants.add(bytes);
                labels.add("0x" + hex);
                candidates.add(new Candidate("HEX_LITERAL_BYTES", functionName, "0x" + hex, bytes));
            }
        }

        // Consecutive immediate windows catch common patterns such as repeated 64-bit stores followed by one XOR loop.
        int maxWindowItems = 12;
        for (int i = 0; i < constants.size(); i++) {
            byte[] acc = new byte[0];
            StringBuilder label = new StringBuilder();
            for (int j = i; j < constants.size() && j < i + maxWindowItems; j++) {
                acc = concat(acc, constants.get(j));
                if (acc.length > MAX_CANDIDATE_BYTES) break;
                if (label.length() > 0) label.append(" ");
                label.append(labels.get(j));
                if (j > i && acc.length >= 8) {
                    candidates.add(new Candidate("HEX_LITERAL_RUN_BYTES", functionName, label.toString(), acc));
                }
            }
        }

        // Treat referenced static data as encrypted byte candidates. No key is read from these symbols.
        Matcher sym = ADDRESS_SYMBOL_PATTERN.matcher(content);
        Set<String> seenSymbols = new HashSet<>();
        while (sym.find()) {
            String prefix = sym.group(1);
            String hexAddr = sym.group(2);
            String symbolKey = prefix + "_" + hexAddr;
            if (!seenSymbols.add(symbolKey)) continue;
            for (int size : likelyReadSizesForPrefix(prefix)) {
                byte[] data = readBytesAt(hexToLong(hexAddr), size);
                if (data != null && data.length >= MIN_XOR_INPUT_LENGTH && !isAllSameByte(data)) {
                    candidates.add(new Candidate("SYMBOL_BYTES", functionName, symbolKey + ":" + size, data));
                }
            }
        }

        return candidates;
    }

    private List<XorKey> extractXorKeysFromReferencedSymbols(String content) {
        List<XorKey> keys = new ArrayList<>();
        if (content == null || content.isEmpty()) return keys;

        Matcher matcher = ADDRESS_SYMBOL_PATTERN.matcher(content);
        Set<String> seenSymbols = new HashSet<>();
        while (matcher.find()) {
            String prefix = matcher.group(1);
            String hexAddr = matcher.group(2);
            String symbolName = prefix + "_" + hexAddr;
            if (!seenSymbols.add(symbolName)) continue;

            for (int size : likelyKeySizesForPrefix(prefix)) {
                byte[] bytes = readBytesFromSymbol(symbolName, size);
                if (bytes == null || bytes.length == 0) {
                    bytes = readBytesAt(hexToLong(hexAddr), size);
                }
                if (bytes == null || bytes.length == 0) continue;
                if (!looksLikeUsefulKey(bytes)) continue;
                keys.add(new XorKey("dynamic_" + symbolName + "_len" + bytes.length, bytes));
            }
        }
        return keys;
    }

    private int[] likelyKeySizesForPrefix(String prefix) {
        String p = prefix == null ? "" : prefix.toLowerCase();
        if (p.equals("byte")) return new int[] { 1, 4, 8, 16 };
        if (p.equals("word")) return new int[] { 2, 4, 8, 16 };
        if (p.equals("dword")) return new int[] { 4, 8, 16, 32 };
        if (p.equals("qword")) return new int[] { 8, 16, 32 };
        if (p.equals("xmmword")) return new int[] { 16, 32, 64, 80 };
        if (p.equals("ymmword")) return new int[] { 32, 64, 80 };
        return new int[] { 8, 16, 32, 64, 80 };
    }

    private boolean looksLikeUsefulKey(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return false;
        if (isAllSameByte(bytes)) return false;
        int zeros = 0;
        int ff = 0;
        for (byte b : bytes) {
            int v = b & 0xff;
            if (v == 0) zeros++;
            if (v == 0xff) ff++;
        }
        if (zeros > bytes.length / 2) return false;
        if (ff > bytes.length / 2) return false;
        return true;
    }

    private void addUniqueXorKeys(List<XorKey> target, List<XorKey> incoming) {
        if (target == null || incoming == null) return;
        Set<String> existing = new HashSet<>();
        for (XorKey key : target) {
            if (key != null && key.bytes != null) existing.add(toHex(key.bytes));
        }
        for (XorKey key : incoming) {
            if (key == null || key.bytes == null || key.bytes.length == 0) continue;
            String hex = toHex(key.bytes);
            if (existing.add(hex)) target.add(key);
        }
    }

    private int[] likelyReadSizesForPrefix(String prefix) {
        String p = prefix.toLowerCase();
        if (p.equals("byte")) return new int[] { 8, 16, 32, 64 };
        if (p.equals("word")) return new int[] { 8, 16, 32, 64 };
        if (p.equals("dword")) return new int[] { 4, 8, 16, 32, 64 };
        if (p.equals("qword")) return new int[] { 8, 16, 32, 64 };
        if (p.equals("xmmword")) return new int[] { 16, 32, 64, 80 };
        if (p.equals("ymmword")) return new int[] { 32, 64, 80 };
        return new int[] { 16, 32, 64, 80, 128 };
    }

    private List<XorFinding> deobfuscateExtractedStrings(List<ExtractedString> strings, Set<String> dedupe, int maxFindings) {
        List<Candidate> candidates = buildStringCandidates(strings);
        if (!dynamicXorKeys.isEmpty()) {
            return decodeWithDynamicXorKeys(candidates, dedupe, maxFindings);
        }
        return bruteForceSingleByteXor(candidates, dedupe, maxFindings);
    }

    private List<XorFinding> bruteForceSingleByteXor(List<Candidate> candidates, Set<String> dedupe, int maxFindings) {
        List<XorFinding> findings = new ArrayList<>();
        addDynamicKeyFindings(findings, candidates, dedupe, maxFindings);
        if (findings.size() >= maxFindings) return findings;

        for (Candidate candidate : candidates) {
            if (candidate.bytes.length < MIN_XOR_INPUT_LENGTH) continue;
            for (int k = 1; k < 256; k++) {
                byte[] decoded = xorWithByte(candidate.bytes, k);
                addInterestingSegments(findings, dedupe, candidate, String.format("single_byte_0x%02X", k), decoded, maxFindings);
                if (findings.size() >= maxFindings) return findings;
            }
        }
        return findings;
    }

    private List<XorFinding> decodeWithDynamicXorKeys(List<Candidate> candidates, Set<String> dedupe, int maxFindings) {
        List<XorFinding> findings = new ArrayList<>();
        addDynamicKeyFindings(findings, candidates, dedupe, maxFindings);
        return findings;
    }

    private void addDynamicKeyFindings(List<XorFinding> findings, List<Candidate> candidates, Set<String> dedupe, int maxFindings) {
        if (dynamicXorKeys.isEmpty()) return;
        for (Candidate candidate : candidates) {
            if (candidate.bytes.length < MIN_XOR_INPUT_LENGTH) continue;
            for (XorKey key : dynamicXorKeys) {
                int maxAlign = Math.max(1, Math.min(key.bytes.length, 16));
                for (int align = 0; align < maxAlign; align++) {
                    byte[] decoded = xorWithRepeatingKey(candidate.bytes, key.bytes, align);
                    addInterestingSegments(findings, dedupe, candidate, key.name + ":align" + align, decoded, maxFindings);
                    if (findings.size() >= maxFindings) return;
                }
            }
        }
    }

    private void addInterestingSegments(List<XorFinding> findings, Set<String> dedupe, Candidate candidate,
                                        String keyName, byte[] decoded, int maxFindings) {
        List<String> segments = printableSegments(decoded);
        for (String segment : segments) {
            double score = scoreDecodedText(segment);
            if (score < 5.0) continue;
            String key = candidate.functionName + "|" + candidate.sourceType + "|" + keyName + "|" + segment;
            if (!dedupe.add(key)) continue;
            findings.add(new XorFinding(candidate.functionName, candidate.sourceType, candidate.label, keyName,
                                        segment, score, toHex(candidate.bytes)));
            if (findings.size() >= maxFindings) return;
        }
    }

    private List<String> printableSegments(byte[] decoded) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (byte value : decoded) {
            int b = value & 0xff;
            if ((b >= 0x20 && b <= 0x7e) || b == '\t') {
                sb.append((char) b);
            } else {
                flushSegment(out, sb);
            }
        }
        flushSegment(out, sb);
        return out;
    }

    private void flushSegment(List<String> out, StringBuilder sb) {
        if (sb.length() >= MIN_XOR_INPUT_LENGTH) {
            String s = sb.toString().trim();
            if (s.length() >= MIN_XOR_INPUT_LENGTH) out.add(s);
        }
        sb.setLength(0);
    }

    private double scoreDecodedText(String s) {
        if (s == null) return -100.0;
        String text = s.trim();
        int len = text.length();
        if (len < MIN_XOR_INPUT_LENGTH || len > 220) return -100.0;

        int printable = 0;
        int alpha = 0;
        int digit = 0;
        int usefulPunct = 0;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 32 && c <= 126) printable++;
            if (Character.isLetter(c)) alpha++;
            if (Character.isDigit(c)) digit++;
            if ("./:_-?=&%\\\\".indexOf(c) >= 0) usefulPunct++;
        }
        double printableRatio = (double) printable / Math.max(1, len);
        if (printableRatio < 0.92) return -100.0;

        String lower = text.toLowerCase();
        double score = 0.0;
        score += printableRatio * 3.0;
        score += Math.min(4.0, (alpha + digit) / 4.0);
        score += Math.min(3.0, usefulPunct / 2.0);

        if (DOMAIN_PATTERN.matcher(text).matches()) score += 8.0;
        if (lower.contains("http://") || lower.contains("https://")) score += 10.0;
        if (lower.contains("/dns-query") || lower.contains("dns.google") || lower.contains("api")) score += 6.0;
        if (lower.contains(".dll") || lower.contains("ntdll") || lower.contains("kernel32") || lower.contains("wininet")) score += 7.0;
        if (lower.contains("getprocaddress") || lower.contains("loadlibrary") || lower.contains("internetopen") || lower.contains("cryptstring")) score += 7.0;
        if (lower.contains("createprocess") || lower.contains("virtualalloc") || lower.contains("writeprocessmemory")) score += 7.0;
        if (containsCommonWords(text)) score += 3.0;

        boolean likelyIndicator = score >= 10.0;
        if (!likelyIndicator && alpha < 3) return -100.0;
        if (!likelyIndicator && (alpha + digit) < Math.max(3, len / 3)) return -100.0;

        int maxRun = 1;
        int curRun = 1;
        for (int i = 1; i < text.length(); i++) {
            if (text.charAt(i) == text.charAt(i - 1)) {
                curRun++;
                maxRun = Math.max(maxRun, curRun);
            } else {
                curRun = 1;
            }
        }
        if (maxRun > Math.max(8, len / 2)) return -100.0;

        return score;
    }

    private List<Candidate> buildStringCandidates(List<ExtractedString> strings) {
        List<Candidate> candidates = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (ExtractedString s : strings) {
            if (s == null || s.processedString == null) continue;
            byte[] bytes = s.processedString.getBytes(StandardCharsets.ISO_8859_1);
            if (bytes.length < MIN_XOR_INPUT_LENGTH || bytes.length > MAX_CANDIDATE_BYTES) continue;
            if (isAllSameByte(bytes)) continue;
            String baseType = s.encoding == null || s.encoding.isEmpty() ? "EXTRACTED_STRING" : s.encoding;
            String sourceType = "STRING_BYTES_" + baseType;
            String area = s.functionName == null || s.functionName.isEmpty() ? "<strings>" : s.functionName;
            String label = s.rawString == null ? s.processedString : s.rawString;
            String key = sourceType + "|" + area + "|" + label;
            if (!seen.add(key)) continue;
            candidates.add(new Candidate(sourceType, area, label, bytes));
        }
        return candidates;
    }

    private void addRawAsciiStringsFromMemory(Program program, List<ExtractedString> allStrings) {
        if (program == null || allStrings == null) return;
        Set<String> seen = new HashSet<>();
        int totalScanned = 0;
        int added = 0;

        try {
            Memory memory = program.getMemory();
            for (MemoryBlock block : memory.getBlocks()) {
                if (added >= MAX_RAW_ASCII_STRINGS) break;
                if (!block.isInitialized() || block.isOverlay()) continue;
                if (block.getSize() <= 0 || block.getSize() > Integer.MAX_VALUE) continue;
                if (block.getSize() > MAX_MEMORY_BLOCK_SCAN_BYTES) continue;
                if (totalScanned + block.getSize() > MAX_TOTAL_MEMORY_SCAN_BYTES) break;

                byte[] bytes = new byte[(int) block.getSize()];
                try {
                    block.getBytes(block.getStart(), bytes);
                    totalScanned += bytes.length;
                } catch (Exception e) {
                    continue;
                }

                int start = -1;
                for (int i = 0; i <= bytes.length; i++) {
                    int b = i < bytes.length ? (bytes[i] & 0xff) : -1;
                    boolean printable = b >= 0x20 && b <= 0x7e;
                    if (printable) {
                        if (start == -1) start = i;
                    } else if (start != -1) {
                        int len = i - start;
                        if (len >= MIN_XOR_INPUT_LENGTH && len <= MAX_CANDIDATE_BYTES) {
                            String value = new String(bytes, start, len, StandardCharsets.ISO_8859_1);
                            String dedupe = block.getName() + "|" + value;
                            if (seen.add(dedupe)) {
                                allStrings.add(new ExtractedString(value, value, "RAW_ASCII", "<memory:" + block.getName() + ">"));
                                added++;
                                if (added >= MAX_RAW_ASCII_STRINGS) break;
                            }
                        }
                        start = -1;
                    }
                }
            }
        } catch (Exception ignored) {
            // Best-effort raw string extraction from memory.
        }
    }

    private List<XorFinding> scanMemorySingleByteXor(Memory memory, Set<String> dedupe, int maxFindings) {
        List<XorFinding> findings = new ArrayList<>();
        int totalScanned = 0;

        for (MemoryBlock block : memory.getBlocks()) {
            if (findings.size() >= maxFindings) break;
            if (!block.isInitialized() || block.isOverlay()) continue;
            if (block.getSize() <= 0 || block.getSize() > Integer.MAX_VALUE) continue;
            if (block.getSize() > MAX_MEMORY_BLOCK_SCAN_BYTES) continue;
            if (totalScanned + block.getSize() > MAX_TOTAL_MEMORY_SCAN_BYTES) break;

            byte[] bytes = new byte[(int) block.getSize()];
            try {
                block.getBytes(block.getStart(), bytes);
                totalScanned += bytes.length;
            } catch (Exception e) {
                continue;
            }

            Candidate candidate = new Candidate("MEMORY_BLOCK_BYTES", "<memory>", block.getName(), bytes);
            for (int k = 1; k < 256; k++) {
                byte[] decoded = xorWithByte(bytes, k);
                List<String> segments = printableSegments(decoded);
                for (String segment : segments) {
                    double score = scoreDecodedText(segment);
                    if (score < 12.0) continue;
                    String key = "<memory>|" + block.getName() + "|" + String.format("single_byte_0x%02X", k) + "|" + segment;
                    if (!dedupe.add(key)) continue;
                    findings.add(new XorFinding("<memory>", "MEMORY_BLOCK_BYTES", block.getName(),
                                                String.format("single_byte_0x%02X", k), segment, score, ""));
                    if (findings.size() >= maxFindings) return findings;
                }
            }
        }
        return findings;
    }

    private List<ExtractedString> extractDefinedDataStrings(Program program) {
        List<ExtractedString> strings = new ArrayList<>();
        try {
            for (Data data : program.getListing().getDefinedData(true)) {
                if (data.getDataType() == null) continue;
                String typeName = data.getDataType().getName().toLowerCase();
                if (!typeName.contains("string")) continue;
                Object val = data.getValue();
                if (val != null) {
                    String s = val.toString();
                    strings.add(new ExtractedString(s, s, "DEFINED_DATA", "<data>"));
                }
            }
        } catch (Exception ignored) {
            // Best-effort defined-data string extraction.
        }
        return strings;
    }

    private List<Candidate> buildDefinedDataCandidates(Program program) {
        List<Candidate> candidates = new ArrayList<>();
        try {
            for (Data data : program.getListing().getDefinedData(true)) {
                if (data == null || data.getLength() <= 0 || data.getLength() > MAX_CANDIDATE_BYTES) continue;
                Address address = data.getAddress();
                if (address == null) continue;
                byte[] bytes = new byte[data.getLength()];
                int read = currentProgram.getMemory().getBytes(address, bytes);
                if (read > 0) {
                    if (read < bytes.length) bytes = Arrays.copyOf(bytes, read);
                    if (bytes.length >= MIN_XOR_INPUT_LENGTH && !isAllSameByte(bytes)) {
                        candidates.add(new Candidate("DEFINED_DATA_BYTES", "<data>", address.toString(), bytes));
                    }
                }
            }
        } catch (Exception ignored) {
            // Best-effort defined-data candidate extraction.
        }
        return candidates;
    }

    private void writeFindings(PrintWriter writer, List<XorFinding> findings) {
        if (findings.isEmpty()) {
            writer.println("No XOR brute-force findings.");
            return;
        }

        if (!debugMode) {
            int count = 0;
            Set<String> seenDecoded = new LinkedHashSet<>();
            for (XorFinding f : findings) {
                if (f == null || f.decoded == null || f.decoded.isEmpty()) continue;
                if (!seenDecoded.add(f.decoded)) continue;
                writer.printf("%4d: %s%n", ++count, repr(f.decoded));
            }
            if (count == 0) writer.println("No XOR brute-force findings.");
            return;
        }

        for (int i = 0; i < findings.size(); i++) {
            XorFinding f = findings.get(i);
            writer.printf("%4d: %s%n", i + 1, repr(f.decoded));
            writer.printf("      Function/Area: %s%n", f.functionName);
            writer.printf("      Source: %s%n", f.sourceType);
            writer.printf("      Candidate: %s%n", f.candidateLabel);
            writer.printf("      Key: %s%n", f.keyName);
            writer.printf("      Score: %.2f%n", f.score);
            if (f.rawHex != null && !f.rawHex.isEmpty()) {
                writer.printf("      RawHex: %s%n", f.rawHex);
            }
            writer.println();
        }
    }

    private void writeCombinedDecodedStrings(PrintWriter writer, List<XorFinding> findings) {
        if (findings == null || findings.isEmpty()) {
            writer.println("No deobfuscated strings.");
            return;
        }

        int count = 0;
        Set<String> seenDecoded = new LinkedHashSet<>();
        for (XorFinding f : findings) {
            if (f == null || f.decoded == null || f.decoded.isEmpty()) continue;
            if (!seenDecoded.add(f.decoded)) continue;
            writer.printf("%4d: %s%n", ++count, repr(f.decoded));
            if (debugMode) {
                writer.printf("      Function/Area: %s%n", f.functionName);
                writer.printf("      Source: %s%n", f.sourceType);
                writer.printf("      Candidate: %s%n", f.candidateLabel);
                writer.printf("      Key: %s%n", f.keyName);
                writer.printf("      Score: %.2f%n", f.score);
                if (f.rawHex != null && !f.rawHex.isEmpty()) {
                    writer.printf("      RawHex: %s%n", f.rawHex);
                }
                writer.println();
            }
        }
        if (count == 0) writer.println("No deobfuscated strings.");
    }

    private byte[] readBytesAt(long addressValue, int size) {
        try {
            Address address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(Long.toHexString(addressValue));
            if (address == null || !currentProgram.getMemory().contains(address)) return null;
            byte[] bytes = new byte[size];
            int read = currentProgram.getMemory().getBytes(address, bytes);
            if (read <= 0) return null;
            if (read < size) return Arrays.copyOf(bytes, read);
            return bytes;
        } catch (Exception e) {
            return null;
        }
    }

    private long hexToLong(String hex) {
        return Long.parseUnsignedLong(hex, 16);
    }

    private byte[] littleEndianBytesFromHexLiteral(String hex) {
        String h = hex;
        if ((h.length() % 2) != 0) h = "0" + h;
        int byteCount = h.length() / 2;
        byte[] big = new byte[byteCount];
        for (int i = 0; i < byteCount; i++) {
            big[i] = (byte) Integer.parseInt(h.substring(i * 2, i * 2 + 2), 16);
        }
        byte[] little = new byte[byteCount];
        for (int i = 0; i < byteCount; i++) {
            little[i] = big[byteCount - 1 - i];
        }
        return little;
    }

    private byte[] xorWithByte(byte[] input, int key) {
        byte[] out = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            out[i] = (byte) ((input[i] & 0xff) ^ key);
        }
        return out;
    }

    private byte[] xorWithRepeatingKey(byte[] input, byte[] key, int align) {
        byte[] out = new byte[input.length];
        if (key == null || key.length == 0) return out;
        for (int i = 0; i < input.length; i++) {
            out[i] = (byte) ((input[i] & 0xff) ^ (key[(i + align) % key.length] & 0xff));
        }
        return out;
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private boolean isAllSameByte(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return true;
        byte first = bytes[0];
        for (byte b : bytes) {
            if (b != first) return false;
        }
        return true;
    }

    private String unescapeCString(String s) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c != '\\') {
                out.append(c);
                i++;
                continue;
            }
            i++;
            if (i >= s.length()) {
                out.append('\\');
                break;
            }
            char esc = s.charAt(i++);
            switch (esc) {
                case 'n': out.append('\n'); break;
                case 'r': out.append('\r'); break;
                case 't': out.append('\t'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case '\\': out.append('\\'); break;
                case '\'': out.append('\''); break;
                case '"': out.append('"'); break;
                case '0': out.append((char) 0); break;
                case 'x':
                case 'X': {
                    int val = 0;
                    int digits = 0;
                    while (i < s.length() && digits < 2) {
                        int d = Character.digit(s.charAt(i), 16);
                        if (d == -1) break;
                        val = (val << 4) + d;
                        i++;
                        digits++;
                    }
                    if (digits == 0) {
                        out.append("\\x");
                    } else {
                        out.append((char) val);
                    }
                    break;
                }
                case 'u': {
                    int val = 0;
                    int start = i;
                    int count = 0;
                    while (i < s.length() && count < 4) {
                        int d = Character.digit(s.charAt(i), 16);
                        if (d == -1) break;
                        val = (val << 4) + d;
                        i++;
                        count++;
                    }
                    if (count == 4) {
                        out.append((char) val);
                    } else {
                        out.append("\\u");
                        i = start;
                    }
                    break;
                }
                default: {
                    if (esc >= '0' && esc <= '7') {
                        int val = esc - '0';
                        int count = 1;
                        while (i < s.length() && count < 3) {
                            char h = s.charAt(i);
                            if (h < '0' || h > '7') break;
                            val = val * 8 + (h - '0');
                            i++;
                            count++;
                        }
                        out.append((char) val);
                    } else {
                        out.append('\\').append(esc);
                    }
                }
            }
        }
        return out.toString();
    }

    private boolean containsCommonWords(String text) {
        if (text == null) return false;
        String lower = text.toLowerCase();
        String[] commonWords = {
            "the", "and", "for", "with", "from", "this", "that", "http", "https", "user", "host", "path",
            "open", "read", "write", "close", "load", "proc", "addr", "error", "query", "api", "dll", "exe",
            "kernel", "ntdll", "wininet", "crypto", "process", "thread", "mutex", "server", "client", "domain"
        };
        for (String word : commonWords) {
            if (lower.contains(word)) return true;
        }
        return false;
    }

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
                        result.append("\\x00");
                    } else if (c >= 32 && c <= 126) {
                        result.append(c);
                    } else {
                        result.append(String.format("\\x%02x", (int) c & 0xff));
                    }
            }
        }
        result.append("'");
        return result.toString();
    }

    private String toHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }

    private boolean isDebugModeEnabled() {
        try {
            String[] args = getScriptArgs();
            if (args == null) return false;
            for (String arg : args) {
                if (arg == null) continue;
                String a = arg.trim().toLowerCase();
                if (a.equals("debug") || a.equals("--debug") || a.equals("/debug") ||
                    a.equals("debug=true") || a.equals("-debug")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
            // Debug mode is off by default.
        }
        return false;
    }

    private byte[] readBytesFromSymbol(String symbolName, int size) {
        if (symbolName == null || symbolName.isEmpty() || size <= 0) return null;
        try {
            SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(symbolName);
            while (symbols.hasNext()) {
                Symbol symbol = symbols.next();
                if (symbol == null || symbol.getAddress() == null) continue;
                byte[] bytes = new byte[size];
                int read = currentProgram.getMemory().getBytes(symbol.getAddress(), bytes);
                if (read <= 0) continue;
                if (read < size) return Arrays.copyOf(bytes, read);
                return bytes;
            }
        } catch (Exception ignored) {
            // Best-effort symbol key lookup.
        }

        // Fallback for decompiler-style symbols: parse the hex suffix as an address
        // and read the bytes directly.
        try {
            int idx = symbolName.lastIndexOf('_');
            if (idx >= 0 && idx + 1 < symbolName.length()) {
                String hex = symbolName.substring(idx + 1);
                if (hex.matches("[0-9a-fA-F]{6,16}")) {
                    return readBytesAt(Long.parseUnsignedLong(hex, 16), size);
                }
            }
        } catch (Exception ignored) {
            // Fall through.
        }
        return null;
    }

    private String getOriginalFileCommentPath(Program program) {
        if (program == null) return "<unknown>";

        try {
            Object executablePath = program.getClass().getMethod("getExecutablePath").invoke(program);
            if (executablePath != null) {
                String path = executablePath.toString();
                if (path != null && !path.trim().isEmpty()) {
                    return path.trim().replace('\\', '/');
                }
            }
        } catch (Exception ignored) {
            // Some Ghidra versions/loaders may not expose executable path here.
        }

        try {
            if (program.getDomainFile() != null) {
                String path = program.getDomainFile().getPathname();
                if (path != null && !path.trim().isEmpty()) {
                    return path.trim().replace('\\', '/');
                }
            }
        } catch (Exception ignored) {
            // Fall through to program name.
        }

        try {
            String name = program.getName();
            if (name != null && !name.trim().isEmpty()) return name.trim();
        } catch (Exception ignored) {
            // Fall through.
        }

        return "<unknown>";
    }

    private long estimateProgramSize(Program program) {
        try {
            long total = 0;
            for (MemoryBlock block : program.getMemory().getBlocks()) {
                if (block.isInitialized() && !block.isOverlay()) {
                    total += block.getSize();
                }
            }
            return total;
        } catch (Exception e) {
            return -1;
        }
    }

    private Path getOutputDir() {
        String programDataDir = System.getenv("ProgramData");
        if (programDataDir == null || programDataDir.isEmpty()) {
            programDataDir = "C:\\ProgramData";
        }
        return Paths.get(programDataDir, "HydraDragonAntivirus", "decompiled");
    }

    private Path getUniqueFilePath(Path outputDir, String baseFileName, String fileExtension) {
        Path filePath = outputDir.resolve(baseFileName + fileExtension);
        int fileIndex = 1;
        while (Files.exists(filePath)) {
            filePath = outputDir.resolve(baseFileName + "_" + fileIndex + fileExtension);
            fileIndex++;
        }
        return filePath;
    }

    private String sanitizeFileName(String name) {
        if (name == null) return "program";
        String normalized = Normalizer.normalize(name, Normalizer.Form.NFKD);
        String replaced = normalized.replaceAll("[\\\\/:*?\"<>|]", "_");
        replaced = replaced.replaceAll("\\p{Cntrl}+", "").trim();
        while (replaced.endsWith(".") || replaced.endsWith(" ")) {
            replaced = replaced.substring(0, replaced.length() - 1);
        }
        replaced = replaced.replaceAll("_+", "_");
        if (replaced.isEmpty()) replaced = "program";
        int maxLen = 200;
        if (replaced.length() > maxLen) replaced = replaced.substring(0, maxLen);
        return replaced;
    }

    private static class ExtractedString {
        final String rawString;
        final String processedString;
        final String encoding;
        final String functionName;

        ExtractedString(String rawString, String processedString, String encoding, String functionName) {
            this.rawString = rawString;
            this.processedString = processedString;
            this.encoding = encoding;
            this.functionName = functionName;
        }
    }

    private static class Candidate {
        final String sourceType;
        final String functionName;
        final String label;
        final byte[] bytes;

        Candidate(String sourceType, String functionName, String label, byte[] bytes) {
            this.sourceType = sourceType;
            this.functionName = functionName;
            this.label = label;
            this.bytes = bytes == null ? new byte[0] : bytes;
        }
    }

    private static class XorKey {
        final String name;
        final byte[] bytes;

        XorKey(String name, byte[] bytes) {
            this.name = name;
            this.bytes = bytes == null ? new byte[0] : bytes;
        }
    }

    private static class XorFinding {
        final String functionName;
        final String sourceType;
        final String candidateLabel;
        final String keyName;
        final String decoded;
        final double score;
        final String rawHex;

        XorFinding(String functionName, String sourceType, String candidateLabel, String keyName,
                   String decoded, double score, String rawHex) {
            this.functionName = functionName;
            this.sourceType = sourceType;
            this.candidateLabel = candidateLabel;
            this.keyName = keyName;
            this.decoded = decoded;
            this.score = score;
            this.rawHex = rawHex;
        }
    }
}
