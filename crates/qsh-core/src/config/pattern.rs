//! Host patterns as in ssh_config(5): `*` and `?` wildcards, `!` negation, lists separated by
//! commas or spaces, compared without regard to ASCII case.

use std::fmt;

/// A list of host patterns, the name of a `[host."pattern"]` table.
///
/// The list matches a host when one of its plain patterns matches and none of its negated
/// patterns does; a list of negated patterns alone matches nothing (as in ssh).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternList {
    text: String,
    patterns: Vec<Pattern>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Pattern {
    negated: bool,
    glob: Vec<u8>,
}

impl PatternList {
    /// Parse a pattern list. Fails on an empty list or an empty pattern (`"a,,b"`, `"!"`).
    pub fn parse(text: &str) -> Result<PatternList, String> {
        let mut patterns = Vec::new();
        for group in text.split(',') {
            let group = group.trim();
            if group.is_empty() {
                return Err(format!("empty pattern in {text:?}"));
            }
            for item in group.split_ascii_whitespace() {
                let (negated, glob) = match item.strip_prefix('!') {
                    Some(rest) => (true, rest),
                    None => (false, item),
                };
                if glob.is_empty() {
                    return Err(format!("empty pattern in {text:?}"));
                }
                patterns.push(Pattern {
                    negated,
                    glob: glob.as_bytes().to_vec(),
                });
            }
        }
        Ok(PatternList {
            text: text.to_string(),
            patterns,
        })
    }

    /// True when the list matches one of `names` and no negated pattern matches any of them.
    pub fn matches(&self, names: &[&str]) -> bool {
        let mut matched = false;
        for pattern in &self.patterns {
            for name in names {
                if glob(&pattern.glob, name.as_bytes()) {
                    if pattern.negated {
                        return false;
                    }
                    matched = true;
                }
            }
        }
        matched
    }
}

impl fmt::Display for PatternList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// Match `text` against a pattern with `*` (any run of bytes) and `?` (one byte), ignoring
/// ASCII case. Linear backtracking on the last `*`: no exponential blow-up.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    // Where the last `*` was, and the text position it is currently taken to end at
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(b'*') => {
                star = Some((p, t));
                p += 1;
            }
            Some(&c) if c == b'?' || c.eq_ignore_ascii_case(&text[t]) => {
                p += 1;
                t += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    p = sp + 1;
                    t = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

/// The host part of an ssh destination, as host patterns see it: `user@host` gives `host`, and
/// `ssh://user@host:port` gives `host` (`[::1]` gives `::1`).
pub fn destination_host(destination: &str) -> &str {
    let Some(uri) = destination.strip_prefix("ssh://") else {
        return destination.rsplit_once('@').map_or(destination, |(_, host)| host);
    };
    let authority = uri.split('/').next().unwrap_or(uri);
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    if let Some(bracketed) = host_port.strip_prefix('[') {
        return bracketed.split(']').next().unwrap_or(bracketed);
    }
    host_port.split(':').next().unwrap_or(host_port)
}
