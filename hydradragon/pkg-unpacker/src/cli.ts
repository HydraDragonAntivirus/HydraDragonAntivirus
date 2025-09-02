import { Command } from "commander";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

import Unpacker from "./unpacker";

class Cli {
    private program: Command;

    constructor() {
        this.program = new Command();
    }

    private setup() {
        this.program
            .name("pkg-unpacker")
            .requiredOption(
                "-i, --input <file>",
                "Specify the input binary file path",
            )
            .option(
                "-o, --output <folder>",
                "Specify the output folder path",
                ".",
            )
            .option("--run", "Run the unpacked binary", false);

        this.program.parse();

        const options = this.program.opts();

        if (!options.input || !options.output) {
            console.error("Both -i (input) and -o (output) are required.");
            process.exit(1);
        }

        const inputPath = path.resolve(options.input);
        const outputPath = path.resolve(options.output);

        if (!fs.existsSync(inputPath)) {
            console.error("The provided binary file does not exist!");
            process.exit(1);
        }

        return {
            inputPath,
            outputPath,
            shouldRun: options.run as boolean,
        };
    }

    public async run() {
        const { inputPath, outputPath, shouldRun } = this.setup();

        const unpacker = await Unpacker.create(inputPath);

        await unpacker.unpack(outputPath, shouldRun);
    }
}

export default Cli;
