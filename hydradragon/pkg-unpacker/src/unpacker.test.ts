import test, { describe } from "node:test";
import Unpacker from "./unpacker";
import { CompressionType, type Props } from "./types";
import assert from "node:assert/strict";

describe("pkg 5.8.1 (latest) - linux", () => {
    const prelude: Props = {
        vfs: {
            "/snapshot/pkg/index.js": { "0": [0, 560], "3": [560, 118] },
            "/snapshot/pkg": { "2": [678, 12], "3": [690, 117] },
            "/snapshot": { "2": [807, 7], "3": [814, 117] },
        },
        entryPoint: "/snapshot/pkg/index.js",
        symlinks: {},
        filesDict: {},
        doCompress: CompressionType.NONE,
    };

    test("can find VFS entry", () => {
        const unpacker = new Unpacker("N/A", prelude, -1);

        const vfsEntry = unpacker["findVirtualFileSystemEntry"](
            prelude.entryPoint,
        );

        assert.deepStrictEqual(prelude.vfs[prelude.entryPoint], vfsEntry);
    });
});

describe("pkg 5.8.1 (latest) - linux - gzip", () => {
    const prelude: Props = {
        vfs: {
            "0/1/2/3": { "0": [0, 363], "3": [363, 99] },
            "0/1/2": { "2": [462, 32], "3": [494, 100] },
            "0/1": { "2": [594, 27], "3": [621, 100] },
        },
        entryPoint: "/snapshot/pkg/index.js",
        symlinks: {},
        filesDict: { "": "0", snapshot: "1", pkg: "2", "index.js": "3" },
        doCompress: CompressionType.GZIP,
    };

    test("can uncompress path", () => {
        const unpacker = new Unpacker("N/A", prelude, -1);

        const compressedPath = "0/1/2/3";
        const uncompressedPath = unpacker["toOriginal"](compressedPath);
        const expectedPath = prelude.entryPoint;

        assert.equal(uncompressedPath, expectedPath);
    });

    test("can find VFS entry", () => {
        const unpacker = new Unpacker("N/A", prelude, -1);

        const compressedPath = "0/1/2/3";
        const vfsEntry = unpacker["findVirtualFileSystemEntry"](
            unpacker["toOriginal"](compressedPath),
        );

        assert.deepStrictEqual(prelude.vfs[compressedPath], vfsEntry);
    });
});

describe("pkg 5.2.0 - linux - gzip", () => {
    const prelude: Props = {
        vfs: {
            "0$1$2$3": { "0": [0, 383], "1": [383, 51], "3": [434, 99] },
            "0$1$2": { "2": [533, 32], "3": [565, 100] },
            "0$1": { "2": [665, 34], "3": [699, 100] },
        },
        entryPoint: "/snapshot/vercel_pkg/index.js",
        symlinks: {},
        filesDict: { "": "0", snapshot: "1", vercel_pkg: "2", "index.js": "3" },
        doCompress: CompressionType.GZIP,
    };

    test("can uncompress path", () => {
        const unpacker = new Unpacker("N/A", prelude, -1);

        const compressedPath = "0$1$2$3";
        const uncompressedPath = unpacker["toOriginal"](compressedPath);
        const expectedPath = prelude.entryPoint;

        assert.equal(uncompressedPath, expectedPath);
    });

    test("can find VFS entry", () => {
        const unpacker = new Unpacker("N/A", prelude, -1);

        const compressedPath = "0$1$2$3";
        const vfsEntry = unpacker["findVirtualFileSystemEntry"](
            unpacker["toOriginal"](compressedPath),
        );

        assert.deepStrictEqual(prelude.vfs[compressedPath], vfsEntry);
    });
});

describe("pkg 5.8.1 (latest) - windows", () => {
    const prelude: Props = {
        vfs: {
            "C:\\snapshot\\pkg\\index.js": { "0": [0, 560], "3": [560, 118] },
            "C:\\snapshot\\pkg": { "2": [678, 12], "3": [690, 117] },
            "C:\\snapshot": { "2": [807, 7], "3": [814, 117] },
        },
        entryPoint: "C:\\snapshot\\pkg\\index.js",
        symlinks: {},
        filesDict: {},
        doCompress: CompressionType.NONE,
    };

    test("can find VFS entry", () => {
        const unpacker = new Unpacker("N/A", prelude, -1);

        const vfsEntry = unpacker["findVirtualFileSystemEntry"](
            prelude.entryPoint,
        );

        assert.deepStrictEqual(prelude.vfs[prelude.entryPoint], vfsEntry);
    });
});

describe("pkg 5.8.1 (latest) - windows - gzip", () => {
    const prelude: Props = {
        vfs: {
            "0/1/2/3": { "0": [0, 362], "3": [362, 99] },
            "0/1/2": { "2": [461, 32], "3": [493, 100] },
            "0/1": { "2": [593, 27], "3": [620, 100] },
        },
        entryPoint: "C:\\snapshot\\pkg\\index.js",
        symlinks: {},
        filesDict: { "C:": "0", snapshot: "1", pkg: "2", "index.js": "3" },
        doCompress: CompressionType.GZIP,
    };

    test("can uncompress path", () => {
        const unpacker = new Unpacker("N/A", prelude, -1);

        const compressedPath = "0/1/2/3";
        const uncompressedPath = unpacker["toOriginal"](compressedPath);
        const expectedPath = prelude.entryPoint;

        assert.equal(uncompressedPath, expectedPath);
    });

    test("can find VFS entry", () => {
        const unpacker = new Unpacker("N/A", prelude, -1);

        const compressedPath = "0/1/2/3";
        const vfsEntry = unpacker["findVirtualFileSystemEntry"](
            unpacker["toOriginal"](compressedPath),
        );

        assert.deepStrictEqual(prelude.vfs[compressedPath], vfsEntry);
    });
});
