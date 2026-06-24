//! Differential fuzzing of the optimized matcher paths against a brute-force
//! ground truth. For thousands of random (pattern, buffer) pairs we assert that
//! the SIMD/prefilter-accelerated `find_all` and `find_all_at` return EXACTLY the
//! matches that a position-by-position `match_at` reference finds. Any divergence
//! — especially a match the fast path misses — is a false negative bug.
//!
//! Deterministic: a fixed-seed xorshift PRNG, so a failure reproduces. The brute
//! reference uses `Pattern::match_at` (the recursive verifier) at every position,
//! which is independent of the anchoring/threading logic under test.

use hydradragonclamav::pattern::{compile_pattern_variants, Modifiers, Pattern};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

/// Generate a random ClamAV-ish hex body plus, optionally, a concrete byte
/// instance that matches it (for embedding so match paths are exercised).
/// Returns (body_string, Option<matching_instance>).
fn gen_pattern(rng: &mut Rng) -> (String, Vec<u8>) {
    let ntokens = 2 + rng.below(5); // 2..6 tokens
    let mut body = String::new();
    let mut instance: Vec<u8> = Vec::new();
    let mut used_gap = false;
    let mut used_alt = false;

    for ti in 0..ntokens {
        // No leading/trailing gap; at most one gap and one alternation.
        let can_gap = ti != 0 && ti != ntokens - 1 && !used_gap;
        let can_alt = !used_alt;
        let kind = rng.below(10);
        match kind {
            0..=4 => {
                // literal byte
                let b = rng.byte();
                body.push_str(&format!("{:02X}", b));
                instance.push(b);
            }
            5 => {
                // ?? wildcard
                body.push_str("??");
                instance.push(rng.byte());
            }
            6 => {
                // high nibble X?
                let hi = rng.below(16) as u8;
                body.push_str(&format!("{:X}?", hi));
                instance.push((hi << 4) | (rng.byte() & 0x0f));
            }
            7 => {
                // low nibble ?X
                let lo = rng.below(16) as u8;
                body.push_str(&format!("?{:X}", lo));
                instance.push(((rng.byte() & 0x0f) << 4) | lo);
            }
            8 if can_alt => {
                used_alt = true;
                let nbr = 2 + rng.below(2); // 2..3 branches
                let mut branches: Vec<Vec<u8>> = Vec::new();
                for _ in 0..nbr {
                    let blen = 1 + rng.below(3); // 1..3 bytes per branch
                    let mut br = Vec::new();
                    for _ in 0..blen {
                        br.push(rng.byte());
                    }
                    branches.push(br);
                }
                body.push('(');
                for (i, br) in branches.iter().enumerate() {
                    if i > 0 {
                        body.push('|');
                    }
                    for b in br {
                        body.push_str(&format!("{:02X}", b));
                    }
                }
                body.push(')');
                // realize: pick one branch
                let pick = rng.below(branches.len());
                instance.extend_from_slice(&branches[pick]);
            }
            9 if can_gap => {
                used_gap = true;
                let g = rng.below(3);
                let (txt, min) = match g {
                    0 => ("{2}".to_string(), 2usize),
                    1 => ("{1-3}".to_string(), 1usize),
                    _ => ("*".to_string(), 0usize),
                };
                body.push_str(&txt);
                // realize: emit exactly `min` arbitrary bytes (always within range)
                for _ in 0..min {
                    instance.push(rng.byte());
                }
            }
            _ => {
                // fallback to a literal byte
                let b = rng.byte();
                body.push_str(&format!("{:02X}", b));
                instance.push(b);
            }
        }
    }
    (body, instance)
}

/// Replicates `pattern::is_fullword`: a match is full-word when the byte before
/// its start and the byte at its end are both non-alphanumeric (or absent).
fn is_fullword(data: &[u8], start: usize, end: usize) -> bool {
    let before = start
        .checked_sub(1)
        .and_then(|i| data.get(i))
        .map_or(false, |b| b.is_ascii_alphanumeric());
    let after = data.get(end).map_or(false, |b| b.is_ascii_alphanumeric());
    !before && !after
}

/// Brute-force ground truth: every position where the pattern verifies (honoring
/// the `fullword` flag, which `find_all`/`find_all_at` also apply).
fn brute(p: &Pattern, data: &[u8], fullword: bool) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for pos in 0..=data.len() {
        if let Some(end) = p.match_at(data, pos) {
            if fullword && !is_fullword(data, pos, end) {
                continue;
            }
            out.push((pos, end));
        }
    }
    out
}

fn as_pairs(v: &[hydradragonclamav::pattern::MatchRange]) -> Vec<(usize, usize)> {
    let mut p: Vec<(usize, usize)> = v.iter().map(|m| (m.start, m.end)).collect();
    p.sort_unstable();
    p.dedup();
    p
}

#[test]
fn differential_find_all_matches_bruteforce() {
    const ITERS: usize = 40_000;
    const LIMIT: usize = 1_000_000;
    let seeds = [
        0x1234_5678_9abc_def1u64,
        0xdead_beef_cafe_0001,
        0x0f1e_2d3c_4b5a_6978,
    ];

    let mut tested = 0usize;
    let mut with_atom = 0usize;

  for seed in seeds {
    let mut rng = Rng(seed);
    for it in 0..ITERS {
        let (body, instance) = gen_pattern(&mut rng);
        // nocase/fullword sometimes; not wide (wide changes the byte layout, a
        // separate concern). fullword is exercised against a replicated filter.
        let modifiers = Modifiers {
            nocase: rng.below(4) == 0,
            fullword: rng.below(4) == 0,
            ..Default::default()
        };
        let variants = match compile_pattern_variants(&body, modifiers) {
            Ok(v) if !v.is_empty() => v,
            _ => continue,
        };
        let p = &variants[0];
        if p.instructions.is_empty() {
            continue;
        }

        // Build a buffer: half random, half with the matching instance embedded.
        let base_len = 6 + rng.below(40);
        let mut data: Vec<u8> = (0..base_len).map(|_| rng.byte()).collect();
        if rng.below(2) == 0 && !instance.is_empty() && !modifiers.nocase {
            let at = rng.below(data.len().max(1));
            let mut buf = data[..at.min(data.len())].to_vec();
            buf.extend_from_slice(&instance);
            buf.extend_from_slice(&data[at.min(data.len())..]);
            data = buf;
        }

        let reference = brute(p, &data, modifiers.fullword);
        let full = vec![(0usize, data.len())];

        // 1) find_all (anchored SIMD fast-path) must equal brute force.
        let fa = as_pairs(&p.find_all(&data, &full, LIMIT));
        assert_eq!(
            fa, reference,
            "find_all != brute\n  iter={it}\n  body={body}\n  nocase={}\n  data={:02x?}\n  find_all={:?}\n  brute={:?}",
            modifiers.nocase, data, fa, reference
        );

        // 2) find_all_at (prefilter-threaded) must equal brute force, given hints =
        //    all occurrences of the indexed atom (exact best_literal, or the
        //    lowercased nocase run — found in the lowercased buffer), capped at 16.
        let atom_info: Option<(Vec<u8>, bool)> = p
            .required_atom()
            .map(|a| (a.into_iter().take(16).collect::<Vec<u8>>(), false))
            .or_else(|| {
                p.required_atom_nocase()
                    .map(|a| (a.into_iter().take(16).collect::<Vec<u8>>(), true))
            });
        if let Some((atom, nocase)) = atom_info {
            if atom.len() >= 2 {
                with_atom += 1;
                // Nocase atoms are matched against the lowercased buffer (same byte
                // positions), mirroring the prefilter's nocase pass.
                let hay: Vec<u8> = if nocase {
                    data.iter().map(|b| b.to_ascii_lowercase()).collect()
                } else {
                    data.clone()
                };
                let mut hints: Vec<u32> = Vec::new();
                if hay.len() >= atom.len() {
                    for i in 0..=hay.len() - atom.len() {
                        if hay[i..i + atom.len()] == atom[..] {
                            hints.push(i as u32);
                        }
                    }
                }
                let fat = as_pairs(&p.find_all_at(&data, &full, LIMIT, &hints));
                assert_eq!(
                    fat, reference,
                    "find_all_at != brute\n  iter={it}\n  body={body}\n  atom={:02x?}\n  data={:02x?}\n  hints={:?}\n  find_all_at={:?}\n  brute={:?}",
                    atom, data, hints, fat, reference
                );

                // 3) Restricted-range consistency: find_all and find_all_at must
                //    agree on an arbitrary sub-range (adjudicates the pat_len vs
                //    min_len range-bound concern). Compare the two optimized paths.
                if data.len() >= 4 {
                    let rs = rng.below(data.len() / 2);
                    let re = rs + 1 + rng.below(data.len() - rs);
                    let range = vec![(rs, re)];
                    let r_fa = as_pairs(&p.find_all(&data, &range, LIMIT));
                    let r_fat = as_pairs(&p.find_all_at(&data, &range, LIMIT, &hints));
                    assert_eq!(
                        r_fa, r_fat,
                        "find_all vs find_all_at diverge on range [{rs},{re})\n  iter={it}\n  body={body}\n  atom={:02x?}\n  data={:02x?}\n  find_all={:?}\n  find_all_at={:?}",
                        atom, data, r_fa, r_fat
                    );
                }
            }
        }
        tested += 1;
    }
  }

    // Sanity: the harness actually exercised a meaningful number of cases.
    assert!(tested > ITERS, "too many skipped: {tested}");
    assert!(with_atom > 2000, "too few atom-bearing patterns: {with_atom}");
    eprintln!("differential: {tested} patterns tested, {with_atom} with atoms");
}
