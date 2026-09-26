//! 手写 JSON 的公共小工具：字符串转义与数字输出。

/// 返回合法的 JSON 字符串字面量（含首尾引号）。
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// 数字输出；NaN/Infinity 不合法，统一写 0。
pub fn push_num(out: &mut String, n: f64) {
    if !n.is_finite() {
        out.push('0');
    } else {
        out.push_str(&format!("{:.4}", n));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes() {
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_str("行\n"), "\"行\\n\"");
        assert_eq!(json_str("\u{1}"), "\"\\u0001\"");
    }

    #[test]
    fn numbers() {
        let mut s = String::new();
        push_num(&mut s, f64::NAN);
        assert_eq!(s, "0");
        s.clear();
        push_num(&mut s, 1.5);
        assert_eq!(s, "1.5000");
    }
}
