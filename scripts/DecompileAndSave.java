import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.app.util.bin.format.pe.ExportDataDirectory;
import ghidra.app.util.bin.format.pe.ExportInfo;
import ghidra.app.util.bin.format.pe.NTHeader;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

import java.io.PrintWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;

public class DecompileAndSave extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = currentProgram;
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        // Use the current directory from Ghidra and navigate to decompile directory
        String currentDir = currentProgram.getExecutablePath();
        Path outputDir = Paths.get(currentDir).getParent().resolve("decompile");

        // Ensure the directory exists
        try {
            Files.createDirectories(outputDir);
            println("Decompile directory created: " + outputDir.toString());
        } catch (IOException e) {
            println("Failed to create directory: " + e.getMessage());
            return;
        }

        // Determine the filename with a unique suffix if needed
        String baseFileName = "decompiled_function_details";
        String fileExtension = ".txt";
        Path filePath = outputDir.resolve(baseFileName + fileExtension);
        int fileIndex = 1;

        while (Files.exists(filePath)) {
            filePath = outputDir.resolve(baseFileName + "_" + fileIndex + fileExtension);
            fileIndex++;
        }

        println("Saving decompiled code to: " + filePath.toString());

        // Save the original file path as a comment in the first line
        try (PrintWriter out = new PrintWriter(new FileWriter(filePath.toFile()))) {
            out.println("// Original file: " + currentProgram.getExecutablePath());
            out.println();
        } catch (IOException e) {
            println("Error writing to file: " + e.getMessage());
            return;
        }

        // Function Manager to retrieve all functions
        if (!program.getFunctionManager().getFunctions(true).hasNext()) {
            println("No functions found in the program.");
            return;
        }

        int functionCount = 0;  // Count of functions processed

        // Extract and combine details for each function
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            println("Processing function: " + func.getName());

            // Decompile to C code
            DecompileResults results = decompiler.decompileFunction(func, 60, TaskMonitor.DUMMY);
            if (!results.decompileCompleted()) {
                println("Decompilation failed for function: " + func.getName());
                continue;
            }

            HighFunction highFunc = results.getHighFunction();
            if (highFunc == null || results.getDecompiledFunction() == null) {
                println("Decompiled function or high-level function is null for: " + func.getName());
                continue;
            }

            String decompiledCode = results.getDecompiledFunction().getC();

            // Extract Pcode (intermediate representation)
            StringBuilder pcodeRepresentation = new StringBuilder();
            if (highFunc.getBasicBlocks() != null) {
                for (PcodeBlock block : highFunc.getBasicBlocks()) {
                    if (block instanceof PcodeBlockBasic) {
                        PcodeBlockBasic basicBlock = (PcodeBlockBasic) block;
                        for (PcodeOpAST pcodeOp : basicBlock.getIterator()) {
                            pcodeRepresentation.append(pcodeOp.toString()).append("\n");
                        }
                    }
                }
            }

            // Extract native assembly code
            StringBuilder nativeAssemblyCode = new StringBuilder();
            Listing listing = program.getListing();
            CodeUnitIterator codeUnits = listing.getCodeUnits(func.getBody(), true);
            while (codeUnits.hasNext()) {
                CodeUnit codeUnit = codeUnits.next();
                if (codeUnit instanceof Instruction) {
                    Instruction instruction = (Instruction) codeUnit;
                    nativeAssemblyCode.append(instruction.toString()).append("\n");
                }
            }

            // Combine and write all details to file
            try (PrintWriter out = new PrintWriter(new FileWriter(filePath.toFile(), true))) {
                out.println("Function: " + func.getName());
                out.println("C Decompilation:");
                out.println(decompiledCode);
                out.println("\nPcode Representation:");
                out.println(pcodeRepresentation.toString());
                out.println("\nNative Assembly Code:");
                out.println(nativeAssemblyCode.toString());
                out.println("\n\n");
            } catch (IOException e) {
                println("Error writing to file: " + e.getMessage());
            }

            functionCount++;  // Increment function count
        }

        // **Now handling export data directory extraction**

        // Extract export information if the program is a PE file and has an Export Data Directory
        NTHeader ntHeader = NTHeader.createNTHeader(currentProgram, this);
        ExportDataDirectory exportDataDir = ntHeader.getOptionalHeader().getExportDataDirectory();

        if (exportDataDir != null && exportDataDir.parse()) {
            ExportInfo[] exports = exportDataDir.getExports();
            try (PrintWriter out = new PrintWriter(new FileWriter(filePath.toFile(), true))) {
                out.println("\nExported Functions:");
                for (ExportInfo export : exports) {
                    // Skip invalid exports
                    if (export == null || export.getName() == null) {
                        println("Invalid or missing export entry.");
                        continue;
                    }

                    out.println("Export Name: " + export.getName() + 
                                ", Address: " + export.getAddress() + 
                                ", Ordinal: " + export.getOrdinal());
                }
            } catch (IOException e) {
                println("Error writing exported functions to file: " + e.getMessage());
            }
        } else {
            println("No export data directory found or failed to parse export directory.");
        }

        println("Decompilation and analysis completed for " + functionCount + " functions. Results saved to " + filePath);
    }
}
