//! 手写 JSON 的公共小工具：序列化（字符串转义、数字输出）与
//! 自产 JSONL 的逐行解析。序列化和解析对着同一套文法，
//! roundtrip 行为由 records.rs 的不变量测试锁定。

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

/// 一个解析出来的 JSON 值。落盘格式只有字符串、数字、bool、null，够用。
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

/// 解析一行扁平 JSON 对象为有序键值对。
/// 任何语法不符（截断、多余逗号、未知转义……）都整行放弃返回 None。
pub fn parse_object(line: &str) -> Option<Vec<(String, Value)>> {
    let bytes = line.as_bytes();
    let mut i = 0usize;
    let mut out = Vec::new();

    fn ws(bytes: &[u8], i: &mut usize) {
        while *i < bytes.len() && matches!(bytes[*i], b' ' | b'\t' | b'\r' | b'\n') {
            *i += 1;
        }
    }

    ws(bytes, &mut i);
    if bytes.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    let mut first = true;
    loop {
        ws(bytes, &mut i);
        match bytes.get(i) {
            // 循环顶的 } 只可能是空对象（首轮）或尾逗号，后者非法
            Some(&b'}') if first => {
                i += 1;
                ws(bytes, &mut i);
                return if i == bytes.len() { Some(out) } else { None };
            }
            Some(&b'"') => {}
            _ => return None,
        }
        first = false;
        let key = parse_string(bytes, &mut i)?;
        ws(bytes, &mut i);
        if bytes.get(i) != Some(&b':') {
            return None;
        }
        i += 1;
        ws(bytes, &mut i);
        let value = parse_value(bytes, &mut i)?;
        out.push((key, value));
        ws(bytes, &mut i);
        match bytes.get(i) {
            Some(&b',') => {
                i += 1;
            }
            Some(&b'}') => {
                i += 1;
                ws(bytes, &mut i);
                return if i == bytes.len() { Some(out) } else { None };
            }
            _ => return None,
        }
    }
}

/// 解析带引号的字符串（光标停在收尾引号之后）。返回还原后的值。
fn parse_string(bytes: &[u8], i: &mut usize) -> Option<String> {
    debug_assert_eq!(bytes.get(*i), Some(&b'"'));
    *i += 1;
    let mut out = String::new();
    loop {
        match bytes.get(*i) {
            None => return None,
            Some(&b'"') => {
                *i += 1;
                return Some(out);
            }
            Some(&b'\\') => {
                *i += 1;
                match bytes.get(*i) {
                    Some(&b'"') => out.push('"'),
                    Some(&b'\\') => out.push('\\'),
                    Some(&b'/') => out.push('/'),
                    Some(&b'n') => out.push('\n'),
                    Some(&b'r') => out.push('\r'),
                    Some(&b't') => out.push('\t'),
                    Some(&b'b') => out.push('\u{8}'),
                    Some(&b'f') => out.push('\u{c}'),
                    Some(&b'u') => {
                        *i += 1;
                        let hex: String = (0..4)
                            .filter_map(|_| bytes.get(*i).map(|b| {
                                *i += 1;
                                *b as char
                            }))
                            .collect();
                        if hex.len() != 4 {
                            return None;
                        }
                        let cp = u32::from_str_radix(&hex, 16).ok()?;
                        // 代理区不是合法码点；json_str 不会写出，外部伪造的行拒绝
                        let ch = char::from_u32(cp).filter(|&c| !(0xd800..=0xdfff).contains(&(c as u32)))?;
                        out.push(ch);
                        continue; // \u 已消费完 4 位，跳过下面的 *i += 1
                    }
                    _ => return None,
                }
                *i += 1;
            }
            // 未经转义的控制字符在 JSON 字符串里非法
            Some(&b) if b < 0x20 => return None,
            // 多字节 UTF-8 按原样搬运；行本身是 &str，序列保证完整
            Some(_) => {
                let start = *i;
                *i += 1;
                while *i < bytes.len() && (bytes[*i] & 0xc0) == 0x80 {
                    *i += 1;
                }
                out.push_str(std::str::from_utf8(&bytes[start..*i]).ok()?);
            }
        }
    }
}

fn parse_value(bytes: &[u8], i: &mut usize) -> Option<Value> {
    match bytes.get(*i) {
        Some(&b'"') => parse_string(bytes, i).map(Value::Str),
        Some(&b't') => {
            expect(bytes, i, b"true")?;
            Some(Value::Bool(true))
        }
        Some(&b'f') => {
            expect(bytes, i, b"false")?;
            Some(Value::Bool(false))
        }
        Some(&b'n') => {
            expect(bytes, i, b"null")?;
            Some(Value::Null)
        }
        Some(&b) if b == b'-' || b.is_ascii_digit() => {
            let start = *i;
            *i += 1;
            while matches!(bytes.get(*i), Some(b) if b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'))
            {
                *i += 1;
            }
            let text = std::str::from_utf8(&bytes[start..*i]).ok()?;
            text.parse::<f64>().ok().map(Value::Num)
        }
        _ => None,
    }
}

fn expect(bytes: &[u8], i: &mut usize, word: &[u8]) -> Option<()> {
    if bytes.get(*i..*i + word.len()) == Some(word) {
        *i += word.len();
        Some(())
    } else {
        None
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

    #[test]
    fn parse_simple_object() {
        let f = parse_object("{\"a\":1,\"b\":\"x\",\"c\":true,\"d\":null}").unwrap();
        assert_eq!(f[0], ("a".into(), Value::Num(1.0)));
        assert_eq!(f[1], ("b".into(), Value::Str("x".into())));
        assert_eq!(f[2], ("c".into(), Value::Bool(true)));
        assert_eq!(f[3], ("d".into(), Value::Null));
        assert_eq!(parse_object("{}").unwrap(), Vec::new());
    }

    #[test]
    fn parse_escapes_and_unicode() {
        let f = parse_object(&format!("{{\"k\":{}}}", json_str("引\"文\\换\n\u{1}"))).unwrap();
        assert_eq!(f[0].1, Value::Str("引\"文\\换\n\u{1}".into()));
        // \uXXXX 形式
        let f = parse_object("{\"k\":\"\\u4e2d\\u6587\"}").unwrap();
        assert_eq!(f[0].1, Value::Str("中文".into()));
        // 负数与指数
        let f = parse_object("{\"k\":-12.5e2}").unwrap();
        assert_eq!(f[0].1, Value::Num(-1250.0));
    }

    #[test]
    fn parse_fake_field_in_value() {
        // 值里出现 "pid": 模式必须不影响解析——这是旧字符串 find 方案的核心缺陷
        let line = format!("{{\"a\":{},\"pid\":7}}", json_str("x = {\"pid\": 1}"));
        let f = parse_object(&line).unwrap();
        assert_eq!(f[0].1, Value::Str("x = {\"pid\": 1}".into()));
        assert_eq!(f[1], ("pid".into(), Value::Num(7.0)));
    }

    #[test]
    fn parse_rejects_malformed() {
        // 截断
        assert!(parse_object("{\"a\":").is_none());
        assert!(parse_object("{\"a\":1").is_none());
        assert!(parse_object("{\"a\":\"x").is_none());
        // 尾逗号 / 缺冒号 / 缺值 / 尾部垃圾 / 代理区 / 未知转义 / 坏数字
        assert!(parse_object("{\"a\":1,}").is_none());
        assert!(parse_object("{\"a\" 1}").is_none());
        assert!(parse_object("{\"a\":,}").is_none());
        assert!(parse_object("{\"a\":1}x").is_none());
        assert!(parse_object("{\"a\":\"\\ud800\"}").is_none());
        assert!(parse_object("{\"a\":\"\\q\"}").is_none());
        assert!(parse_object("{\"a\":12x3}").is_none());
        assert!(parse_object("").is_none());
        assert!(parse_object("[1,2]").is_none());
    }
}
