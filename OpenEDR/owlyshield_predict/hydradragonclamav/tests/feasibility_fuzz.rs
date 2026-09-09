//! Property fuzzing for `LogicalExpr::can_still_match` (the phase-1 short-circuit).
//!
//! The contract: `can_still_match` OVER-approximates matchability — it may return
//! `true` when no real match exists, but it must NEVER return `false` when some
//! completion of the not-yet-evaluated subsignatures would make the expression
//! match. Violating that is a false negative (the scanner would stop scanning a
//! signature that should fire).
//!
//! For random expressions (including the non-monotone `=N`/`<N` compares that make
//! this subtle) and random partial evaluations, we brute-force EVERY completion of
//! the unevaluated subsigs over a small count range and assert:
//!     (some completion matches)  =>  can_still_match == true.

use hydradragonclamav::database::SourceLocation;
use hydradragonclamav::logical::parse_logical_signature;

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
}

const N: usize = 4; // subsignatures 0..4
const MAXC: usize = 4; // brute completion counts 0..=4

fn gen_expr(rng: &mut Rng, depth: usize) -> String {
    if depth == 0 || rng.below(2) == 0 {
        // leaf subsig with optional postfix count comparison
        let i = rng.below(N);
        if rng.below(2) == 0 {
            let op = ["=", "<", ">", "<=", ">=", "=="][rng.below(6)];
            let val = rng.below(MAXC + 1);
            format!("{i}{op}{val}")
        } else {
            format!("{i}")
        }
    } else {
        let a = gen_expr(rng, depth - 1);
        let b = gen_expr(rng, depth - 1);
        let op = if rng.below(2) == 0 { "&" } else { "|" };
        let inner = format!("({a}{op}{b})");
        // sometimes a block-mod compare over the group
        if rng.below(3) == 0 {
            let cop = ["=", "<", ">"][rng.below(3)];
            let val = rng.below(MAXC + 1);
            format!("({inner}){cop}{val}")
        } else {
            inner
        }
    }
}

#[test]
fn can_still_match_never_under_approximates() {
    let src = SourceLocation {
        path: std::sync::Arc::from(std::path::Path::new("fuzz.ldb")),
        line: 1,
    };
    let seeds = [0xa11ce_u64, 0xb0b_cafe, 0xfeed_face_1234];
    let mut checked = 0usize;
    let mut pruned = 0usize;

    for seed in seeds {
        let mut rng = Rng(seed);
        for _ in 0..30_000 {
            let d = 1 + rng.below(3); let expr = gen_expr(&mut rng, d);
            let line = format!("T;Target:0;{expr};41;42;43;44");
            let sig = match parse_logical_signature(&line, src.clone()) {
                Ok((s, _)) => s,
                Err(_) => continue,
            };
            let e = &sig.expression;

            // Random partial evaluation: each subsig is either evaluated (fixed
            // count) or not. Evaluated counts range 0..=MAXC.
            let mut evaluated = [false; N];
            let mut counts = [0usize; N];
            for k in 0..N {
                evaluated[k] = rng.below(2) == 0;
                if evaluated[k] {
                    counts[k] = rng.below(MAXC + 1);
                }
            }

            let csm = e.can_still_match(&counts, &evaluated);
            checked += 1;
            if csm {
                continue; // over-approx may always say "maybe"; only false is risky
            }
            pruned += 1;

            // can_still_match == false ⇒ assert NO completion of the unevaluated
            // subsigs makes the expression match.
            let uneval: Vec<usize> = (0..N).filter(|&k| !evaluated[k]).collect();
            let combos = (MAXC + 1).pow(uneval.len() as u32);
            for c in 0..combos {
                let mut full = counts;
                let mut rem = c;
                for &k in &uneval {
                    full[k] = rem % (MAXC + 1);
                    rem /= MAXC + 1;
                }
                assert!(
                    !e.eval(&full).matched,
                    "can_still_match=false but completion matches (FALSE NEGATIVE)\n  expr={expr}\n  evaluated={evaluated:?}\n  fixed_counts={counts:?}\n  matching_completion={full:?}"
                );
            }
        }
    }
    assert!(checked > 50_000, "too few checked: {checked}");
    eprintln!("feasibility: {checked} checked, {pruned} prune-decisions verified sound");
}

#[test]
fn can_still_match_over_approximates_eval_when_fully_evaluated() {
    // When every subsig is evaluated, `can_still_match` must be an over-approx of
    // `eval`: wherever `eval` matches, `can_still_match` must be true. It may be
    // true while `eval` is false (it never prunes through a `Compare`), which is
    // safe — the scanner uses `eval` for the final verdict, `can_still_match` only
    // to decide whether to keep scanning.
    let src = SourceLocation {
        path: std::sync::Arc::from(std::path::Path::new("fuzz.ldb")),
        line: 1,
    };
    let mut rng = Rng(0x5eed_1234);
    let evaluated = [true; N];
    for _ in 0..40_000 {
        let d = 1 + rng.below(3); let expr = gen_expr(&mut rng, d);
        let line = format!("T;Target:0;{expr};41;42;43;44");
        let sig = match parse_logical_signature(&line, src.clone()) {
            Ok((s, _)) => s,
            Err(_) => continue,
        };
        let mut counts = [0usize; N];
        for c in counts.iter_mut() {
            *c = rng.below(MAXC + 1);
        }
        if sig.expression.eval(&counts).matched {
            assert!(
                sig.expression.can_still_match(&counts, &evaluated),
                "eval matched but can_still_match=false (FALSE NEGATIVE)\n  expr={expr}\n  counts={counts:?}"
            );
        }
    }
}
