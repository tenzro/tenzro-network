//! A helper that writes identity records past the registry's checks exists
//! only in test builds: every `pub fn *_for_test` in this crate's sources is
//! compiled under `cfg(test)` or the `test-support` feature, never in a
//! release build.

use std::path::Path;

fn sources(dir: &Path, out: &mut Vec<(String, String)>) {
    for e in std::fs::read_dir(dir).expect("source dir").flatten() {
        let p = e.path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push((
                p.display().to_string(),
                std::fs::read_to_string(&p).expect("source"),
            ));
        }
    }
}

#[test]
fn every_test_helper_is_compiled_only_for_tests() {
    let mut files = Vec::new();
    sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    let mut helpers = 0;
    for (path, text) in files {
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let t = line.trim_start();
            if !(t.starts_with("pub fn ") && t.contains("_for_test(")) {
                continue;
            }
            helpers += 1;
            let attributes = lines[..i].iter().rev().take_while(|l| {
                l.trim_start().starts_with("#[") || l.trim_start().starts_with("///")
            });
            assert!(
                attributes
                    .clone()
                    .any(|l| l.contains(r#"cfg(any(test, feature = "test-support"))"#)),
                "{path}:{}: `{}` is compiled into release builds",
                i + 1,
                t
            );
        }
    }
    assert!(helpers > 0, "the guard found no test helper to check");
}
