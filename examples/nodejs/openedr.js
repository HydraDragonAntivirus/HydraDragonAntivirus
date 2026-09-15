const koffi = require('koffi');
const path = require('path');

class OpenEdrScanner {
    constructor(dllPath = 'openedr_static.dll', rulesDir = null) {
        if (!path.isAbsolute(dllPath)) {
            dllPath = path.resolve(__dirname, '../../OpenMalwareScannerPortable/openedr_static.dll');
        }

        const lib = koffi.load(dllPath);

        this.fnInit = lib.func('int32_t openedr_static_init(const char *base_rules_dir)');
        this.fnScanFile = lib.func('char* openedr_static_scan_file(const char *file_path)');
        this.fnScanBytes = lib.func('char* openedr_static_scan_bytes(const uint8_t *data, size_t len, const char *file_name)');
        this.fnScanUrl = lib.func('char* openedr_static_scan_url(const char *url)');
        this.fnCheckRegistry = lib.func('char* openedr_static_check_registry(const char *reg_path)');
        this.fnFreeString = lib.func('void openedr_static_free_string(char *s)');

        const res = this.fnInit(rulesDir);
        if (res !== 0) {
            throw new Error(`Failed to initialize OpenEDR static scanner (code: ${res})`);
        }
    }

    _handleStringResult(ptr) {
        if (!ptr) return null;
        try {
            const str = koffi.decode(ptr, 'str');
            return JSON.parse(str);
        } finally {
            this.fnFreeString(ptr);
        }
    }

    scanFile(filePath) {
        const ptr = this.fnScanFile(filePath);
        return this._handleStringResult(ptr);
    }

    scanBytes(buffer, virtualName = 'sample.bin') {
        const ptr = this.fnScanBytes(buffer, buffer.length, virtualName);
        return this._handleStringResult(ptr);
    }

    scanUrl(url) {
        const ptr = this.fnScanUrl(url);
        return this._handleStringResult(ptr);
    }

    checkRegistry(regPath) {
        const ptr = this.fnCheckRegistry(regPath);
        return this._handleStringResult(ptr);
    }
}

module.exports = { OpenEdrScanner };
