//! hydradragonjsdeob: static JavaScript deobfuscation for the scanner.
//!
//! Based on JS-Deobfuscator 2.0.0 by GnU-Chan (Apache-2.0, crates.io
//! `js-deobfuscator`; its GitHub repository is gone), ported to the OXC version the
//! engine uses. Nothing here runs the script: the original's Node.js layers (dynamic
//! evaluation and the obfuscator.io string-array target, which executed the sample's
//! own decoder in `node`) are removed. `packer` unpacks Dean Edwards' P.A.C.K.E.R.
//! (`eval(function(p,a,c,k,e,d){...})`) before parsing.
//!
//! Layer-by-layer, lowest to highest — each layer depends only on layers below it.
//!
//! ## Layers
//!
//! | Layer | Module       | Purpose                                      |
//! |-------|--------------|----------------------------------------------|
//! | 0     | `value`      | Pure JS value computation. No OXC.            |
//! | 1     | `ast`        | OXC AST read/write helpers.                   |
//! | 2     | `scope`      | Symbol resolution, reference tracking.        |
//! | 3     | `fold`       | Static expression folding.                    |
//! | 5     | `transform`  | Semantic transforms (propagation, inlining).  |
//! | 6     | `engine`     | Module trait, convergence loop, public API.    |
//! |       | `format`     | Pre/post normalization.                        |

pub mod value;
pub mod ast;
pub mod scope;
pub mod fold;
pub mod transform;
pub mod packer;
pub mod engine;
pub mod format;
