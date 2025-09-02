export class UnpackerReadError extends Error {
    constructor(message: string) {
        super(
            `${message} This might happen if your binary is not readable or if pkg changed their code.`,
        );
    }
}
