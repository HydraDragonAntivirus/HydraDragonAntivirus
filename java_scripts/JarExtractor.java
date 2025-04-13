import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

public class JarExtractor {
    public static void main(String[] args) {
        // Check if arguments are provided
        if (args.length < 2) {
            System.err.println("Usage: java JarExtractor <jar-file-path> <output-directory>");
            System.exit(1);
        }

        // Path to the JAR file and output directory from arguments
        String jarFilePath = args[0];
        String outputDir = args[1];

        try {
            extractJar(jarFilePath, outputDir);
            System.out.println("Extraction completed successfully!");
        } catch (IOException e) {
            System.err.println("Error during extraction: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void extractJar(String jarFilePath, String outputDir) throws IOException {
        JarFile jarFile = new JarFile(jarFilePath);
        Enumeration<JarEntry> entries = jarFile.entries();
        File outputDirectory = new File(outputDir);

        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            File outputFile = new File(outputDirectory, entry.getName());

            if (entry.isDirectory()) {
                outputFile.mkdirs();
                continue;
            }

            // Ensure parent directories exist
            File parent = outputFile.getParentFile();
            if (!parent.exists()) {
                parent.mkdirs();
            }

            // Write the file
            try (FileInputStream inputStream = new FileInputStream(jarFilePath);
                 FileOutputStream outputStream = new FileOutputStream(outputFile)) {

                jarFile.getInputStream(entry).transferTo(outputStream);
            }
        }
        jarFile.close();
    }
}
