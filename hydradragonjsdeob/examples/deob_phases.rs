//! Heap and arena after each module of one convergence pass over a file, for finding
//! which transform makes `deobfuscate` use a lot of memory. `deob_phases <file.js>`.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use hydradragonjsdeob::engine::module::Module;
use oxc::allocator::Allocator;
use oxc::parser::Parser;
use oxc::semantic::SemanticBuilder;
use oxc::span::SourceType;

struct Peak;
static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Peak {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(l) };
        if !p.is_null() {
            let n = NOW.fetch_add(l.size(), Ordering::Relaxed) + l.size();
            PEAK.fetch_max(n, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) };
        NOW.fetch_sub(l.size(), Ordering::Relaxed);
    }
}

#[global_allocator]
static A: Peak = Peak;

fn mb(n: usize) -> f64 {
    n as f64 / 1048576.0
}

fn main() {
    let src = std::fs::read_to_string(std::env::args().nth(1).expect("file")).expect("read");
    let allocator = Allocator::default();
    let mut program = Parser::new(&allocator, &src, SourceType::mjs()).parse().program;
    let report = |what: &str, allocator: &Allocator| {
        println!("{what:<22} arena {:>7.1} MB  heap now {:>7.1} MB  heap peak {:>7.1} MB", mb(allocator.used_bytes()), mb(NOW.load(Ordering::Relaxed)), mb(PEAK.load(Ordering::Relaxed)));
        PEAK.store(NOW.load(Ordering::Relaxed), Ordering::Relaxed);
    };
    report("parse", &allocator);
    let mut scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
    report("semantic", &allocator);
    use hydradragonjsdeob::transform::*;
    let mut modules: Vec<Box<dyn Module>> = vec![
        Box::new(object::ObjectPropResolver),
        Box::new(constant::ConstantPropagator),
        Box::new(alias::AliasInliner),
        Box::new(proxy::ProxyInliner),
        Box::new(hydradragonjsdeob::fold::StaticFolder),
        Box::new(member::MemberSimplifier),
        Box::new(dead::DeadCodeEliminator),
    ];
    for pass in 1..=3 {
        for m in &mut modules {
            let r = m.transform(&allocator, &mut program, scoping).unwrap();
            scoping = r.scoping;
            report(&format!("{pass} {} ({})", m.name(), r.modifications), &allocator);
            if m.changes_symbols() && r.modifications > 0 {
                scoping = SemanticBuilder::new().build(&program).semantic.into_scoping();
                report("  rebuild scoping", &allocator);
            }
        }
    }
}
