import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Instruction;

import java.io.PrintWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;

public class ExtractFunctionDetails extends GhidraScript {

    @Override
    protected void run() throws Exception {
        Program program = currentProgram;
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);

        // Ensure the directory exists
        String outputDir = "C:\\Program Files\\HydraDragonAntivirus\\decompile";
        Files.createDirectories(Paths.get(outputDir));

        // Determine the filename with a unique suffix if needed
        String baseFileName = "extracted_function_details";
        String fileExtension = ".txt";
        String fileName = baseFileName + fileExtension;
        Path filePath = Paths.get(outputDir, fileName);

        int fileIndex = 1;
        while (Files.exists(filePath)) {
            fileName = baseFileName + "_" + fileIndex + fileExtension;
            filePath = Paths.get(outputDir, fileName);
            fileIndex++;
        }

        // Save the original file path as a comment in the first line
        try (PrintWriter out = new PrintWriter(new FileWriter(filePath.toFile(), true))) {
            out.println("// Original file: " + currentProgram.getExecutablePath());
            out.println();
        } catch (IOException e) {
            println("Error writing to file: " + e.getMessage());
        }

        // Extract and combine details for each function
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            // Decompile to C code
            DecompileResults results = decompiler.decompileFunction(func, 60, TaskMonitor.DUMMY);
            HighFunction highFunc = results.getHighFunction();
            String decompiledCode = results.getDecompiledFunction().getC();

            // Extract Pcode (intermediate representation)
            StringBuilder pcodeRepresentation = new StringBuilder();
            for (PcodeBlock block : highFunc.getBasicBlocks()) {
                if (block instanceof PcodeBlockBasic) {
                    PcodeBlockBasic basicBlock = (PcodeBlockBasic) block;
                    for (PcodeOpAST pcodeOp : basicBlock.getIterator()) {
                        pcodeRepresentation.append(pcodeOp.toString()).append("\n");
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
        }
    }
}
