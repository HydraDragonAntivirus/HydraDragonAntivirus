#!/usr/bin/env python3
"""Export the HydraDragon APK classifier to ONNX + web weight bundle.

Reads the trained Burn weights via the `hydradragonml-export-weights` Rust
helper (which dumps `apk_weights.bin`, the exact little-endian layout that
`openedr_web`'s `src/apk.rs` parses), then builds an ONNX graph with identical
math so desktop/Python (`onnxruntime`) and the browser (manual forward pass)
score APKs the same:

    tokens[int64 N] -> Gather(embedding VOCABx64) -> ReduceMean(axis=0)
      -> Gemm(fc_text 64->32) -> Relu  (text branch)
    engine[float 11] -> Gemm(fc_engine 11->32) -> Relu  (engine branch)
    Concat([text, engine]) -> Gemm(fc_fused 64->32) -> Relu
      -> Gemm(fc_out 32->1) -> Sigmoid -> malware_prob

Two modes:
  1. Convert mode (real model):
       hydradragonml-export-weights --model model.mpk --output apk_weights.bin
       python export_apk_onnx.py --weights-bin apk_weights.bin \\
           --vocab vocab.json --features features.json \\
           --onnx www/models/apk_model.onnx
  2. Cold-start mode (no trained model yet — neutral zeros, sigmoid(0)=0.5,
     so heuristics drive verdicts until training):
       python export_apk_onnx.py --init-zero --vocab-size 20000 \\
           --onnx www/models/apk_model.onnx --weights-bin www/models/apk_weights.bin

Requires: pip install onnx numpy
"""

import argparse
import json
import os
import struct
import sys

MAGIC = b"HAPK"
TEXT_HIDDEN = 32
ENGINE_HIDDEN = 32
FUSED_HIDDEN = 32
EMBED_DIM = 64
ENGINE_FEATURE_COUNT = 11


def read_weights_bin(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 12 or data[0:4] != MAGIC:
        raise ValueError("not an apk_weights.bin (bad magic)")
    vocab_size, embed_dim = struct.unpack_from("<II", data, 4)
    if embed_dim != EMBED_DIM or vocab_size == 0 or vocab_size > 20000:
        raise ValueError(f"bad header vocab={vocab_size} embed={embed_dim}")
    import numpy as np

    floats = np.frombuffer(data[12:], dtype="<f4").astype("float32")
    off = 0

    def take(n):
        nonlocal off
        chunk = floats[off : off + n]
        if chunk.size != n:
            raise ValueError("truncated weights file")
        off += n
        return chunk

    return {
        "vocab_size": vocab_size,
        "embedding": take(vocab_size * EMBED_DIM).reshape(vocab_size, EMBED_DIM),
        "fc_text_w": take(TEXT_HIDDEN * EMBED_DIM).reshape(TEXT_HIDDEN, EMBED_DIM),
        "fc_text_b": take(TEXT_HIDDEN),
        "fc_engine_w": take(ENGINE_HIDDEN * ENGINE_FEATURE_COUNT).reshape(
            ENGINE_HIDDEN, ENGINE_FEATURE_COUNT
        ),
        "fc_engine_b": take(ENGINE_HIDDEN),
        "fc_fused_w": take(FUSED_HIDDEN * (TEXT_HIDDEN + ENGINE_HIDDEN)).reshape(
            FUSED_HIDDEN, TEXT_HIDDEN + ENGINE_HIDDEN
        ),
        "fc_fused_b": take(FUSED_HIDDEN),
        "fc_out_w": take(FUSED_HIDDEN).reshape(1, FUSED_HIDDEN),
        "fc_out_b": take(1),
    }


def write_weights_bin(path, w):
    import numpy as np

    vocab_size = int(w["vocab_size"])
    parts = [MAGIC, struct.pack("<II", vocab_size, EMBED_DIM)]
    for key in (
        "embedding",
        "fc_text_w",
        "fc_text_b",
        "fc_engine_w",
        "fc_engine_b",
        "fc_fused_w",
        "fc_fused_b",
        "fc_out_w",
        "fc_out_b",
    ):
        arr = np.ascontiguousarray(w[key], dtype="<f4")
        parts.append(arr.tobytes())
    with open(path, "wb") as f:
        for p in parts:
            f.write(p)


def zero_weights(vocab_size):
    import numpy as np

    z = lambda *shape: np.zeros(shape, dtype="float32")
    return {
        "vocab_size": vocab_size,
        "embedding": z(vocab_size, EMBED_DIM),
        "fc_text_w": z(TEXT_HIDDEN, EMBED_DIM),
        "fc_text_b": z(TEXT_HIDDEN),
        "fc_engine_w": z(ENGINE_HIDDEN, ENGINE_FEATURE_COUNT),
        "fc_engine_b": z(ENGINE_HIDDEN),
        "fc_fused_w": z(FUSED_HIDDEN, TEXT_HIDDEN + ENGINE_HIDDEN),
        "fc_fused_b": z(FUSED_HIDDEN),
        "fc_out_w": z(1, FUSED_HIDDEN),
        "fc_out_b": z(1),
    }


def build_onnx(path, w):
    try:
        import numpy as np
        from onnx import TensorProto, helper, checker
    except ImportError:
        print("error: pip install onnx numpy", file=sys.stderr)
        sys.exit(2)

    def init(name, arr):
        arr = np.ascontiguousarray(arr, dtype="float32")
        return helper.make_tensor(name, TensorProto.FLOAT, list(arr.shape), arr.ravel().tolist())

    # ONNX Gemm wants [K, N] (transposed vs our row-major [N, K]).
    nodes = [
        helper.make_node("Gather", ["embedding", "tokens"], ["embedded"], axis=0),
        helper.make_node("ReduceMean", ["embedded"], ["pooled"], axes=[0], keepdims=0),
        helper.make_node("Gemm", ["pooled", "fc_text_w_t", "fc_text_b"], ["text"], alpha=1.0, beta=1.0, transB=1),
        helper.make_node("Relu", ["text"], ["text_relu"]),
        helper.make_node("Gemm", ["engine", "fc_engine_w_t", "fc_engine_b"], ["eng"], alpha=1.0, beta=1.0, transB=1),
        helper.make_node("Relu", ["eng"], ["eng_relu"]),
        helper.make_node("Concat", ["text_relu", "eng_relu"], ["fused_in"], axis=0),
        helper.make_node("Gemm", ["fused_in", "fc_fused_w_t", "fc_fused_b"], ["fused"], alpha=1.0, beta=1.0, transB=1),
        helper.make_node("Relu", ["fused"], ["fused_relu"]),
        helper.make_node("Gemm", ["fused_relu", "fc_out_w_t", "fc_out_b"], ["logit"], alpha=1.0, beta=1.0, transB=1),
        helper.make_node("Sigmoid", ["logit"], ["malware_prob"]),
    ]
    graph = helper.make_graph(
        nodes,
        "HydraDragonApkClassifier",
        [
            helper.make_tensor_value_info("tokens", TensorProto.INT64, ["N"]),
            helper.make_tensor_value_info("engine", TensorProto.FLOAT, [ENGINE_FEATURE_COUNT]),
        ],
        [helper.make_tensor_value_info("malware_prob", TensorProto.FLOAT, [1])],
        [
            init("embedding", w["embedding"]),
            init("fc_text_w_t", w["fc_text_w"]),
            init("fc_text_b", w["fc_text_b"]),
            init("fc_engine_w_t", w["fc_engine_w"]),
            init("fc_engine_b", w["fc_engine_b"]),
            init("fc_fused_w_t", w["fc_fused_w"]),
            init("fc_fused_b", w["fc_fused_b"]),
            init("fc_out_w_t", w["fc_out_w"]),
            init("fc_out_b", w["fc_out_b"]),
        ],
    )
    model = helper.make_model(graph, producer_name="hydradragon-export_apk_onnx")
    model.opset_import[0].version = 17
    checker.check_model(model)
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    import onnx

    onnx.save(model, path)
    print(f"wrote ONNX: {path}")


def reference_forward(w, token_ids, engine):
    """Numpy mirror of src/apk.rs forward (used for --self-test)."""
    import numpy as np

    emb = w["embedding"][np.asarray(token_ids, dtype=np.int64)].mean(axis=0)
    text = np.maximum(emb @ w["fc_text_w"].T + w["fc_text_b"], 0)
    eng = np.maximum(np.asarray(engine, dtype="float32") @ w["fc_engine_w"].T + w["fc_engine_b"], 0)
    fused = np.maximum(np.concatenate([text, eng]) @ w["fc_fused_w"].T + w["fc_fused_b"], 0)
    logit = float(fused @ w["fc_out_w"].T + w["fc_out_b"])
    return float(1.0 / (1.0 + np.exp(-np.clip(logit, -30, 30))))


def main():
    ap = argparse.ArgumentParser(description="Export HydraDragon APK classifier to ONNX + web bundle")
    ap.add_argument("--weights-bin", default="apk_weights.bin")
    ap.add_argument("--onnx", default="apk_model.onnx")
    ap.add_argument("--vocab", default=None, help="vocab.json to copy next to outputs")
    ap.add_argument("--features", default=None, help="features.json to copy next to outputs")
    ap.add_argument("--init-zero", action="store_true", help="cold-start neutral weights")
    ap.add_argument("--vocab-size", type=int, default=20000)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.init_zero or not os.path.exists(args.weights_bin):
        if not args.init_zero and not os.path.exists(args.weights_bin):
            print(f"weights not found ({args.weights_bin}), writing cold-start zeros", file=sys.stderr)
        w = zero_weights(args.vocab_size)
        write_weights_bin(args.weights_bin, w)
        print(f"wrote web weights: {args.weights_bin} ({os.path.getsize(args.weights_bin)} bytes)")
    else:
        w = read_weights_bin(args.weights_bin)
        print(f"loaded weights: vocab={w['vocab_size']} ({os.path.getsize(args.weights_bin)} bytes)")

    build_onnx(args.onnx, w)

    for src in (args.vocab, args.features):
        if not src:
            continue
        if not os.path.exists(src):
            print(f"warning: {src} not found, skipping copy", file=sys.stderr)
            continue
        dst = os.path.join(os.path.dirname(os.path.abspath(args.onnx)), os.path.basename(src))
        if os.path.abspath(src) != os.path.abspath(dst):
            with open(src, "rb") as fsrc, open(dst, "wb") as fdst:
                fdst.write(fsrc.read())
            print(f"copied {src} -> {dst}")

    if args.self_test:
        p0 = reference_forward(w, [1, 2, 3], [0.5] * 11)
        print(f"self-test neutral-ish forward: {p0:.4f} (cold-start expect ~0.5000)")
        # ONNX runtime check when available.
        try:
            import numpy as np
            import onnxruntime as ort

            sess = ort.InferenceSession(args.onnx, providers=["CPUExecutionProvider"])
            out = sess.run(
                ["malware_prob"],
                {"tokens": np.array([1, 2, 3], dtype=np.int64), "engine": np.array([0.5] * 11, dtype=np.float32)},
            )[0]
            print(f"onnxruntime forward: {float(out[0]):.4f}")
        except ImportError:
            print("onnxruntime not installed, skipping runtime check")


if __name__ == "__main__":
    main()
