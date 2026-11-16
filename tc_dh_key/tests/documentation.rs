//! Every public function, every method a type implements, and every helper on
//! a secret path documents its timing.

/// Declaration prefixes whose doc comments must state their timing.
const DECLARATIONS: &[&str] = &[
    "pub fn ",
    "pub const fn ",
    "pub(crate) fn ",
    "fn init(",
    "fn generate_key_pair(",
    "fn fmt(",
    "fn drop(",
    "fn eq(",
    "fn default(",
    "fn private_value(",
    "fn private_range(",
    "fn public_value(",
    "fn has_any_small_factors_safe(",
    "fn rounds(",
    "fn safe_prime_gen2(",
];

fn missing_timing_docs(source: &str) -> (usize, Vec<String>) {
    let mut docs = String::new();
    let mut attribute_depth = 0_i32;
    let mut checked = 0;
    let mut missing = Vec::new();
    for line in source.lines().map(str::trim) {
        // Helpers inside test modules are not part of the contract.
        if line == "#[cfg(test)]" {
            break;
        }
        if let Some(comment) = line.strip_prefix("///") {
            // Lines join with a space, so that a classification may wrap.
            docs.push_str(comment.trim());
            docs.push(' ');
            continue;
        }
        if line.starts_with("#[") || attribute_depth > 0 {
            attribute_depth += line.chars().filter(|&c| c == '[').count() as i32;
            attribute_depth -= line.chars().filter(|&c| c == ']').count() as i32;
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if DECLARATIONS.iter().any(|prefix| line.starts_with(prefix)) {
            checked += 1;
            let docs = docs.to_ascii_lowercase();
            if docs.contains("constant time") == docs.contains("variable time") {
                missing.push(line.to_owned());
            }
        }
        docs.clear();
    }
    (checked, missing)
}

#[test]
fn the_scanner_requires_exactly_one_timing_classification_on_each_declaration() {
    let fixture = "\
/// Constant time.
pub fn documented() {}
pub fn undocumented() {}
/// VARIABLE TIME.
#[inline]
pub const fn accepted() {}
/// Constant time and variable time.
fn rounds() {}
/// Wrapped, constant
/// time.
fn fmt() {}
fn helper() {}
#[cfg(test)]
mod tests {
    fn rounds() {}
}
";
    let (checked, missing) = missing_timing_docs(fixture);
    assert_eq!(checked, 5);
    assert_eq!(missing, ["pub fn undocumented() {}", "fn rounds() {}"]);
}

#[test]
fn every_public_api_and_secret_path_has_an_unambiguous_timing_doc() {
    for (name, source) in [
        ("error.rs", include_str!("../src/error.rs")),
        (
            "group_generator.rs",
            include_str!("../src/group_generator.rs"),
        ),
        (
            "key_pair_generator.rs",
            include_str!("../src/key_pair_generator.rs"),
        ),
        ("math.rs", include_str!("../src/math.rs")),
        (
            "params/group_generation_params.rs",
            include_str!("../src/params/group_generation_params.rs"),
        ),
        (
            "params/key_generation_params.rs",
            include_str!("../src/params/key_generation_params.rs"),
        ),
        (
            "params/parameters.rs",
            include_str!("../src/params/parameters.rs"),
        ),
        (
            "params/private_key.rs",
            include_str!("../src/params/private_key.rs"),
        ),
        (
            "params/public_key.rs",
            include_str!("../src/params/public_key.rs"),
        ),
        (
            "params/validation_parameters.rs",
            include_str!("../src/params/validation_parameters.rs"),
        ),
        (
            "standard_groups.rs",
            include_str!("../src/standard_groups.rs"),
        ),
    ] {
        let (checked, missing) = missing_timing_docs(source);
        assert!(checked > 0, "no declarations scanned in {name}");
        assert!(
            missing.is_empty(),
            "missing timing docs in {name}: {missing:?}"
        );
    }
}
