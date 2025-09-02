import zlib from "node:zlib";

export const gunzip = (buf: zlib.InputType, options: zlib.ZlibOptions = {}) => {
    return new Promise<Buffer<ArrayBufferLike>>((resolve, reject) => {
        zlib.gunzip(buf, options, (err, res) => {
            if (!err) resolve(res);
            else reject(err);
        });
    });
};

export const brotliDecompress = (
    buf: zlib.InputType,
    options: zlib.BrotliOptions = {},
) => {
    return new Promise<Buffer<ArrayBufferLike>>((resolve, reject) => {
        zlib.brotliDecompress(buf, options, (err, res) => {
            if (!err) resolve(res);
            else reject(err);
        });
    });
};
