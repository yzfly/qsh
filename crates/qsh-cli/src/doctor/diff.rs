//! A unified diff of two small texts (the files `tune` writes are a few lines long): longest
//! common subsequence of lines, hunks with three lines of context.

/// `--- a/path` / `+++ b/path` and the hunks turning `old` into `new`; a missing file is
/// `/dev/null`. Empty when they are equal.
pub fn unified(path: &str, old: Option<&str>, new: Option<&str>) -> String {
    let a: Vec<&str> = old.map(|t| t.lines().collect()).unwrap_or_default();
    let b: Vec<&str> = new.map(|t| t.lines().collect()).unwrap_or_default();
    if old == new {
        return String::new();
    }
    let ops = edit_script(&a, &b);
    let from = if old.is_some() {
        format!("a{path}")
    } else {
        "/dev/null".into()
    };
    let to = if new.is_some() {
        format!("b{path}")
    } else {
        "/dev/null".into()
    };
    let mut out = format!("--- {from}\n+++ {to}\n");
    for hunk in hunks(&ops, 3) {
        let (mut a_start, mut a_len, mut b_start, mut b_len) = (0, 0, 0, 0);
        let mut first = true;
        let mut body = String::new();
        for op in &ops[hunk.0..hunk.1] {
            if first {
                a_start = op.a;
                b_start = op.b;
                first = false;
            }
            match op.kind {
                Kind::Same => {
                    a_len += 1;
                    b_len += 1;
                    body.push_str(&format!(" {}\n", a[op.a]));
                }
                Kind::Del => {
                    a_len += 1;
                    body.push_str(&format!("-{}\n", a[op.a]));
                }
                Kind::Add => {
                    b_len += 1;
                    body.push_str(&format!("+{}\n", b[op.b]));
                }
            }
        }
        // Line numbers are 1-based; an empty side starts at 0
        let a_first = if a_len == 0 { a_start } else { a_start + 1 };
        let b_first = if b_len == 0 { b_start } else { b_start + 1 };
        out.push_str(&format!("@@ -{a_first},{a_len} +{b_first},{b_len} @@\n{body}"));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Same,
    Del,
    Add,
}

/// One line of the edit script, with its positions in both texts.
#[derive(Debug, Clone, Copy)]
struct Op {
    kind: Kind,
    a: usize,
    b: usize,
}

fn edit_script(a: &[&str], b: &[&str]) -> Vec<Op> {
    // lcs[i][j]: the longest common subsequence of a[i..] and b[j..]
    let mut lcs = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut ops = Vec::new();
    while i < a.len() || j < b.len() {
        if i < a.len() && j < b.len() && a[i] == b[j] {
            ops.push(Op {
                kind: Kind::Same,
                a: i,
                b: j,
            });
            i += 1;
            j += 1;
        } else if i < a.len() && (j == b.len() || lcs[i + 1][j] >= lcs[i][j + 1]) {
            // Removed lines before added ones, as diff(1) prints them
            ops.push(Op {
                kind: Kind::Del,
                a: i,
                b: j,
            });
            i += 1;
        } else {
            ops.push(Op {
                kind: Kind::Add,
                a: i,
                b: j,
            });
            j += 1;
        }
    }
    ops
}

/// Ranges of `ops` to print: every change with up to `context` unchanged lines around it,
/// merging hunks that touch.
fn hunks(ops: &[Op], context: usize) -> Vec<(usize, usize)> {
    let mut out: Vec<(usize, usize)> = Vec::new();
    for (k, op) in ops.iter().enumerate() {
        if op.kind == Kind::Same {
            continue;
        }
        let start = k.saturating_sub(context);
        let end = (k + context + 1).min(ops.len());
        match out.last_mut() {
            Some(last) if start <= last.1 => last.1 = end,
            _ => out.push((start, end)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_file_changed_file_and_removed_file() {
        assert_eq!(
            unified("/etc/x.conf", None, Some("a\nb\n")),
            "--- /dev/null\n+++ b/etc/x.conf\n@@ -0,0 +1,2 @@\n+a\n+b\n"
        );
        assert_eq!(
            unified("/etc/x.conf", Some("a\nb\nc\n"), Some("a\nB\nc\n")),
            "--- a/etc/x.conf\n+++ b/etc/x.conf\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"
        );
        assert_eq!(
            unified("/etc/x.conf", Some("a\n"), None),
            "--- a/etc/x.conf\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-a\n"
        );
        assert_eq!(unified("/x", Some("same\n"), Some("same\n")), "");
    }

    #[test]
    fn distant_changes_get_their_own_hunks() {
        let old: String = (1..=20).map(|i| format!("l{i}\n")).collect();
        let new = old.replace("l2\n", "two\n").replace("l19\n", "nineteen\n");
        let d = unified("/f", Some(&old), Some(&new));
        assert_eq!(d.matches("@@ -").count(), 2, "{d}");
        assert!(d.contains("@@ -1,5 +1,5 @@\n l1\n-l2\n+two\n l3\n l4\n l5\n"), "{d}");
        assert!(
            d.contains("@@ -16,5 +16,5 @@\n l16\n l17\n l18\n-l19\n+nineteen\n l20\n"),
            "{d}"
        );
    }
}
