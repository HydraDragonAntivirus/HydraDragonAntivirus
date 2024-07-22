import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
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

        // Ensure the directory exists
        String outputDir = "C:\\Program Files\\HydraDragonAntivirus\\decompile";
        Files.createDirectories(Paths.get(outputDir));

        // Determine the filename with a unique suffix if needed
        String baseFileName = "decompiled_output";
        String fileExtension = ".c";
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

        // Decompile all functions
        for (Function func : program.getFunctionManager().getFunctions(true)) {
            DecompileResults results = decompiler.decompileFunction(func, 60, null);
            String decompiledCode = results.getDecompiledFunction().getC();
            
            // Append the decompiled code to the file
            try (PrintWriter out = new PrintWriter(new FileWriter(filePath.toFile(), true))) {
                out.println("Function: " + func.getName());
                out.println(decompiledCode);
                out.println("\n\n");
            } catch (IOException e) {
                println("Error writing to file: " + e.getMessage());
            }
        }
    }
}