//! Every public function, and every trait implementation with a method in
//! it, documents its timing.
//!
//! A trait implementation states it in its own doc, or each of its methods
//! states it in theirs. The scan reads every file under `src`, so new code
//! is held to the same rule without this file changing. It reads lines, not
//! Rust: a declaration's doc is the `///` lines right above it, and a method
//! belongs to the implementation it is indented under. A test module, from
//! `#[cfg(test)]` on, is not read, nor is a file that only a
//! `#[cfg(test)] mod` declares.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// One line of code the scan read: its text, trimmed, how far it is
/// indented, and the doc right above it.
struct Line {
    text: String,
    indent: usize,
    docs: String,
}

/// The `.rs` files under `src`, by their path from it.
fn sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, root: &Path, files: &mut Vec<(String, String)>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, root, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let name = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push((name, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    walk(&root, &root, &mut files);
    files
}

/// The files that only a `#[cfg(test)] mod` declares.
fn test_only(files: &[(String, String)]) -> BTreeSet<String> {
    let mut test_only = BTreeSet::new();
    for (name, source) in files {
        let parent = name.trim_end_matches(".rs");
        let parent = if parent == "lib" {
            String::new()
        } else {
            format!("{parent}/")
        };
        let mut lines = source.lines().map(str::trim);
        while let Some(line) = lines.next() {
            if line == "#[cfg(test)]" {
                let next = lines.next().unwrap_or_default();
                if let Some(module) = next
                    .strip_prefix("mod ")
                    .and_then(|rest| rest.strip_suffix(';'))
                {
                    test_only.insert(format!("{parent}{module}.rs"));
                }
            }
        }
    }
    test_only
}

/// The lines of code in `source`, before its test module.
fn lines_of(source: &str) -> Vec<Line> {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut lines = Vec::new();
    for raw in source.lines() {
        let text = raw.trim();
        let indent = raw.len() - raw.trim_start().len();
        // Helpers inside test modules are not part of the contract.
        if text == "#[cfg(test)]" && indent == 0 {
            break;
        }
        if let Some(comment) = text.strip_prefix("///") {
            // Lines join with a space, so that a classification may wrap.
            docs.push_str(comment.trim());
            docs.push(' ');
            continue;
        }
        if text.starts_with("#[") || text.starts_with("#![") || attribute_depth > 0 {
            attribute_depth += text.matches('[').count() as i32;
            attribute_depth -= text.matches(']').count() as i32;
            continue;
        }
        if text.is_empty() || text.starts_with("//") {
            continue;
        }
        lines.push(Line {
            text: text.to_owned(),
            indent,
            docs: docs.to_ascii_lowercase(),
        });
        docs.clear();
    }
    lines
}

/// Whether `docs` states exactly one of the two timings.
fn states_timing(docs: &str) -> bool {
    docs.contains("constant time") != docs.contains("variable time")
}

/// The declarations of `source` that must state their timing but state
/// none, or both.
fn missing_timing_docs(source: &str) -> Vec<String> {
    let lines = lines_of(source);
    let mut missing = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let text = line.text.as_str();
        if text.starts_with("pub fn ") || text.starts_with("pub const fn ") {
            if !states_timing(&line.docs) {
                missing.push(line.text.clone());
            }
        } else if (text.starts_with("impl ") || text.starts_with("impl<")) && text.contains(" for ")
        {
            let methods: Vec<_> = lines[at + 1..]
                .iter()
                .take_while(|inner| inner.indent > line.indent)
                .filter(|inner| inner.text.starts_with("fn "))
                .collect();
            if methods.is_empty() || states_timing(&line.docs) {
                continue;
            }
            for method in methods {
                if !states_timing(&method.docs) {
                    missing.push(format!("{} / {}", line.text, method.text));
                }
            }
        }
    }
    missing
}

#[test]
fn the_scanner_requires_exactly_one_timing_classification_on_each_declaration() {
    let fixture = "\
/// VARIABLE TIME.
#[inline]
pub fn accepted() {}
pub fn undocumented() {}
/// Constant time and variable time.
pub const fn both() {}
/// Constant time.
impl Trait for Documented {
    fn method() {}
}
impl<T> Trait for PerMethod<T> {
    /// Wrapped, constant
    /// time.
    fn documented() {}
    fn undocumented() {}
}
impl Marker for NoMethods {}
impl Inherent {
    fn private_helper() {}
}
fn free_helper() {}
#[cfg(test)]
mod tests {
    pub fn helper() {}
}
";
    assert_eq!(
        missing_timing_docs(fixture),
        [
            "pub fn undocumented() {}",
            "pub const fn both() {}",
            "impl<T> Trait for PerMethod<T> { / fn undocumented() {}",
        ]
    );
}

#[test]
fn every_public_function_and_trait_implementation_has_an_unambiguous_timing_doc() {
    let files = sources();
    let test_only = test_only(&files);
    assert!(test_only.contains("testing.rs"));
    let mut report = Vec::new();
    for (name, source) in files.iter().filter(|(name, _)| !test_only.contains(name)) {
        for line in missing_timing_docs(source) {
            report.push(format!("{name}: {line}"));
        }
    }
    assert!(
        report.is_empty(),
        "missing timing docs:\n{}",
        report.join("\n")
    );
}
