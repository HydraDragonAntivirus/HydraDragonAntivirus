// unpacker/recipe.rs — the unpack recipe interpreter (format: UNPACK_FORMAT.md).
//
// A recipe is the algorithm that unpacks one packer, written as steps: locate the
// packed data (`find`, `section`, `resource`, `read`, `take`), turn it back into
// the payload (`decompress`, `xor`, `rc4`, ...), and hand the result out
// (`emit`). Where the stub is easier run than described, the emulator steps
// (`run_until`, `mem`, `set_oep`, `dump`) run it and read its memory. Integer
// state lives in variables, byte data in named buffers (`file` is the input).
// Any step that does not hold fails the recipe; `try` / `if` / `repeat` give the
// algorithm its branches and loops.

use crate::unpacker::codecs::{self, Codec};
use crate::unpacker::engine::{entrypoint, Sample, StopHit, Stops, UnpackerEngine};
use crate::unpacker::expr::{Env, Expr};
use hydradragonsig::models::BehaviorTrace;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

/// Bounds of one recipe run.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Instruction budget / time limit of a `run_until` without its own.
    pub max_instructions: usize,
    pub timeout_us: u64,
    /// Largest buffer a step may produce.
    pub max_buffer: usize,
    /// All emitted payloads together.
    pub