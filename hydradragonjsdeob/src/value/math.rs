//! Math.* method evaluation.

use super::JsValue;
use super::coerce::to_number;

/// Evaluate `Math.method(args)`.
pub fn call(method: &str, args: &[JsValue]) -> Option<JsValue> {
    let r = match method {
        // Single-arg
        "abs" => to_number(arg(args, 0)?).abs(),
        "ceil" => to_number(arg(args, 0)?).ceil(),
        "floor" => to_number(arg(args, 0)?).floor(),
        "round" => js_round(to_number(arg(args, 0)?)),
        "trunc" => to_number(arg(args, 0)?).trunc(),
        "sign" => js_sign(to_number(arg(args, 0)?)),
        "sqrt" => to_number(arg(args, 0)?).sqrt(),
        "cbrt" => to_number(arg(args, 0)?).cbrt(),
        "log" => to_number(arg(args, 0)?).ln(),
        "log2" => to_number(arg(args, 0)?).log2(),
        "log10" => to_number(arg(args, 0)?).log10(),
        "log1p" => to_number(arg(args, 0)?).ln_1p(),
        "exp" => to_number(arg(args, 0)?).exp(),
        "expm1" => to_number(arg(args, 0)?).exp_m1(),
        "sin" => to_number(arg(args, 0)?).sin(),
        "cos" => to_number(arg(args, 0)?).cos(),
        "tan" => to_number(arg(args, 0)?).tan(),
        "asin" => to_number(arg(args, 0)?).asin(),
        "acos" => to_number(arg(args, 0)?).acos(),
        "atan" => to_number(arg(args, 0)?).atan(),
        "sinh" => to_number(arg(args, 0)?).sinh(),
        "cosh" => to_number(arg(args, 0)?).cosh(),
        "tanh" => to_number(arg(args, 0)?).tanh(),
        "asinh" => to_number(arg(args, 0)?).asinh(),
        "acosh" => to_number(arg(args, 0)?).acosh(),
        "atanh" => to_number(arg(args, 0)?).atanh(),
        "fround" => (to_number(arg(args, 0)?) as f32) as f64,
        "clz32" => f64::from(super::coerce::to_uint32(arg(args, 0)?).leading_zeros()),

        // Two-arg
        "pow" => to_number(arg(args, 0)?).powf(to_number(arg(args, 1)?)),
        "atan2" => to_number(arg(args, 0)?).atan2(to_number(arg(args, 1)?)),
        "hypot" => {
            let vals: Vec<f64> = args.iter().map(to_number).collect();
            return Some(JsValue::Number(vals.iter().map(|v| v * v).sum::<f64>().sqrt()));
        }
        "imul" => {
            let a = super::coerce::to_int32(arg(args, 0)?);
            let b = super::coerce::to_int32(arg(args, 1)?);
            return Some(JsValue::Number(f64::from(a.wrapping_mul(b))));
        }

        // Variadic
        "max" => {
            if args.is_empty() { return Some(JsValue::Number(f64::NEG_INFINITY)); }
            let mut m = f64::NEG_INFINITY;
            for a in args {
                let n = to_number(a);
                if n.is_nan() { return Some(JsValue::Number(f64::NAN)); }
                if n > m { m = n; }
            }
            return Some(JsValue::Number(m));
        }
        "min" => {
            if args.is_empty() { return Some(JsValue::Number(f64::INFINITY)); }
            let mut m = f64::INFINITY;
            for a in args {
                let n = to_number(a);
                if n.is_nan() { return Some(JsValue::Number(f64::NAN)); }
                if n < m { m = n; }
            }
            return Some(JsValue::Number(m));
        }

        _ => return None,
    };
    Some(JsValue::Number(r))
}

/// Evaluate `Math.CONSTANT`.
pub fn constant(name: &str) -> Option<JsValue> {
    let v = match name {
        "PI" => std::f64::consts::PI,
        "E" => std::f64::consts::E,
        "LN2" => std::f64::consts::LN_2,
        "LN10" => std::f64::consts::LN_10,
        "LOG2E" => std::f64::consts::LOG2_E,
        "LOG10E" => std::f64::consts::LOG10_E,
        "SQRT2" => std::f64::consts::SQRT_2,
        "SQRT1_2" => std::f64::consts::FRAC_1_SQRT_2,
        _ => return None,
    };
    Some(JsValue::Number(v))
}

fn arg(args: &[JsValue], i: usize) -> Option<&JsValue> {
    args.get(i)
}

fn js_round(n: f64) -> f64 {
    if n.is_nan() || n.is_infinite() || n == 0.0 { return n; }
    // JavaScript rounds half-up (0.5 → 1), Rust rounds half-even
    (n + 0.5).floor()
}

fn js_sign(n: f64) -> f64 {
    if n.is_nan() { return f64::NAN; }
    if n == 0.0 { return n; } // preserves -0
    if n > 0.0 { 1.0 } else { -1.0 }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn n(v: f64) -> JsValue { JsValue::Number(v) }

    #[test]
    fn test_basic_math() {
        assert_eq!(call("abs", &[n(-5.0)]), Some(n(5.0)));
        assert_eq!(call("floor", &[n(1.7)]), Some(n(1.0)));
        assert_eq!(call("ceil", &[n(1.1)]), Some(n(2.0)));
        assert_eq!(call("round", &[n(1.5)]), Some(n(2.0)));
        assert_eq!(call("round", &[n(1.4)]), Some(n(1.0)));
        assert_eq!(call("trunc", &[n(1.9)]), Some(n(1.0)));
        assert_eq!(call("sqrt", &[n(9.0)]), Some(n(3.0)));
    }

    #[test]
    fn test_pow_minmax() {
        assert_eq!(call("pow", &[n(2.0), n(10.0)]), Some(n(1024.0)));
        assert_eq!(call("max", &[n(1.0), n(3.0), n(2.0)]), Some(n(3.0)));
        assert_eq!(call("min", &[n(1.0), n(3.0), n(2.0)]), Some(n(1.0)));
        assert_eq!(call("max", &[]), Some(n(f64::NEG_INFINITY)));
        assert_eq!(call("min", &[]), Some(n(f64::INFINITY)));
    }

    #[test]
    fn test_constants() {
        assert_eq!(constant("PI"), Some(n(std::f64::consts::PI)));
        assert_eq!(constant("E"), Some(n(std::f64::consts::E)));
        assert_eq!(constant("unknown"), None);
    }

    #[test]
    fn test_imul() {
        assert_eq!(call("imul", &[n(2.0), n(4.0)]), Some(n(8.0)));
        // Overflow wraps
        assert_eq!(call("imul", &[n(0xFFFF_FFFF_u32 as f64), n(5.0)]), Some(n(-5.0)));
    }

    #[test]
    fn test_clz32() {
        assert_eq!(call("clz32", &[n(1.0)]), Some(n(31.0)));
        assert_eq!(call("clz32", &[n(0.0)]), Some(n(32.0)));
    }
}
