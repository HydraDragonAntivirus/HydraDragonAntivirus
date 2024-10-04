import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.io.PrintWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Iterator;

public class DecompileAndSave extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = currentProgram; // Reference to the current program
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        // Remove leading backslash from executable path and fix slashes
        String executablePath = currentProgram.getExecutablePath().replaceFirst("^/", ""); // Removes leading slash
        executablePath = executablePath.replace("/", "\\");  // Convert to Windows-style path

        // Convert the current directory path to a proper Path object
        Path currentDirPath = Paths.get(System.getProperty("user.dir"));
        Path outputDir = currentDirPath.resolve("decompile");


        // Ensure the directory exists
        try {
            Files.createDirectories(outputDir);
            println("Decompile directory created: " + outputDir.toString());
        } catch (IOException e) {
            println("Failed to create directory: " + e.getMessage());
            return;
        }

        // Base filenames
        String nativeAssemblyBaseFile = "native_assembly";
        String pcodeBaseFile = "pcode_representation";
        String cCodeBaseFile = "c_decompiled";
        String unifiedBaseFile = "unified_output"; // Unified file for all data
        String fileExtension = ".txt";

        // Ensure unique filenames with suffixes
        Path nativeAssemblyFilePath = getUniqueFilePath(outputDir, nativeAssemblyBaseFile, fileExtension);
        Path pcodeFilePath = getUniqueFilePath(outputDir, pcodeBaseFile, fileExtension);
        Path cCodeFilePath = getUniqueFilePath(outputDir, cCodeBaseFile, fileExtension);
        Path unifiedFilePath = getUniqueFilePath(outputDir, unifiedBaseFile, fileExtension); // Path for unified file

        println("Saving native assembly, pcode, C code, and unified output to: " + outputDir.toString());

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

            String decompiledCode = results.getDecompiledFunction().getC();

            // Extract Pcode (intermediate representation)
            StringBuilder pcodeRepresentation = new StringBuilder();
            if (results.getHighFunction().getBasicBlocks() != null) {
                for (PcodeBlock block : results.getHighFunction().getBasicBlocks()) {
                    if (block instanceof PcodeBlockBasic) {
                        PcodeBlockBasic basicBlock = (PcodeBlockBasic) block;
                        Iterator<PcodeOp> iterator = basicBlock.getIterator();
                        while (iterator.hasNext()) {
                            PcodeOp pcodeOp = iterator.next();
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

            // Write C decompiled code to its respective file
            try (PrintWriter out = new PrintWriter(new FileWriter(cCodeFilePath.toFile(), true))) {
                out.println("// Original file: " + executablePath); // Add original file path as a comment
                out.println("Function: " + func.getName());
                out.println(decompiledCode);
                out.println("\n\n");
            } catch (IOException e) {
                println("Error writing C decompiled code: " + e.getMessage());
            }

            // Write Pcode representation to its respective file
            try (PrintWriter out = new PrintWriter(new FileWriter(pcodeFilePath.toFile(), true))) {
                out.println("// Original file: " + executablePath); // Add original file path as a comment
                out.println("Function: " + func.getName());
                out.println(pcodeRepresentation.toString());
                out.println("\n\n");
            } catch (IOException e) {
                println("Error writing Pcode representation: " + e.getMessage());
            }

            // Write native assembly to its respective file
            try (PrintWriter out = new PrintWriter(new FileWriter(nativeAssemblyFilePath.toFile(), true))) {
                out.println("// Original file: " + executablePath); // Add original file path as a comment
                out.println("Function: " + func.getName());
                out.println(nativeAssemblyCode.toString());
                out.println("\n\n");
            } catch (IOException e) {
                println("Error writing native assembly code: " + e.getMessage());
            }

            // Write combined output to the unified file
            try (PrintWriter out = new PrintWriter(new FileWriter(unifiedFilePath.toFile(), true))) {
                out.println("// Original file: " + executablePath); // Add original file path as a comment
                out.println("Function: " + func.getName());
                out.println("C Decompilation:");
                out.println(decompiledCode);
                out.println("\nPcode Representation:");
                out.println(pcodeRepresentation.toString());
                out.println("\nNative Assembly Code:");
                out.println(nativeAssemblyCode.toString());
                out.println("\n\n");
            } catch (IOException e) {
                println("Error writing unified output: " + e.getMessage());
            }

            functionCount++;  // Increment function count
        }

        println("Decompilation and analysis completed for " + functionCount + " functions. Results saved to " + outputDir);
    }

    // Helper method to create unique filenames with suffixes if files already exist
    private Path getUniqueFilePath(Path outputDir, String baseFileName, String fileExtension) {
        Path filePath = outputDir.resolve(baseFileName + fileExtension);
        int fileIndex = 1;

        while (Files.exists(filePath)) {
            filePath = outputDir.resolve(baseFileName + "_" + fileIndex + fileExtension);
            fileIndex++;
        }

        return filePath;
    }
}
