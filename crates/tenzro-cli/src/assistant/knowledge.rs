//! The documentation the Tenzro Assistant answers from. The operator guides
//! are compiled into the binary, cut into one passage per heading, and
//! searched by words. An answer is the passages themselves with where they
//! come from; a question the guides do not cover gets no answer.

use std::collections::{HashMap, HashSet};

/// Where to look when the shipped guides have no answer.
pub const DOCS_URL: &str = "https://docs.tenzro.com";

macro_rules! guides {
    ($($name:literal),* $(,)?) => {
        &[$((concat!("docs/", $name), include_str!(concat!("../../../../docs/", $name)))),*]
    };
}

/// The guides an operator needs, by repository path.
const GUIDES: &[(&str, &str)] = guides![
    "GETTING-STARTED.md",
    "INSTALL.md",
    "GUIDE.md",
    "NODE.md",
    "NODE-NETWORKING.md",
    "ACCESS.md",
    "STORAGE.md",
    "LOAD-PROTECTION.md",
    "COMPUTE.md",
    "NETWORK.md",
    "ECONOMICS.md",
    "TDIP.md",
    "TRUST.md",
    "BRIDGE.md",
];

/// Words too common to tell passages apart.
const COMMON: &[&str] = &[
    "the", "and", "for", "are", "can", "does", "how", "what", "when", "where", "which", "who",
    "why", "with", "you", "your", "that", "this", "from", "have", "has", "not", "but", "its",
    "into", "need", "needs", "tenzro",
];

/// BM25 term saturation and length normalisation.
const K1: f32 = 1.2;
const B: f32 = 0.75;

/// One section of a guide.
#[derive(Debug, PartialEq, Eq)]
pub struct Passage {
    pub guide: &'static str,
    pub heading: &'static str,
    pub text: &'static str,
}

impl Passage {
    /// How an answer names this passage.
    pub fn citation(&self) -> String {
        format!("{} § {}", self.guide, self.heading)
    }
}

/// The searchable guides.
pub struct Pack {
    passages: Vec<Passage>,
    terms: Vec<HashMap<String, f32>>,
    lengths: Vec<f32>,
    in_passages: HashMap<String, f32>,
    mean_length: f32,
}

fn words(text: &str) -> impl Iterator<Item = String> + '_ {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() > 2)
        .map(str::to_lowercase)
        .filter(|w| !COMMON.contains(&w.as_str()))
}

/// Cuts a guide at every heading of level two or deeper, outside code fences.
fn passages_of(guide: &'static str, source: &'static str) -> Vec<Passage> {
    let mut out = Vec::new();
    let mut heading = source
        .lines()
        .next()
        .unwrap_or_default()
        .trim_start_matches('#')
        .trim();
    let (mut start, mut at, mut fenced) = (0, 0, false);
    for line in source.split_inclusive('\n') {
        if line.starts_with("```") {
            fenced = !fenced;
        } else if !fenced && line.starts_with("##") {
            out.push(Passage {
                guide,
                heading,
                text: source[start..at].trim(),
            });
            heading = line.trim_start_matches('#').trim();
            start = at + line.len();
        }
        at += line.len();
    }
    out.push(Passage {
        guide,
        heading,
        text: source[start..].trim(),
    });
    out.retain(|p| !p.text.is_empty());
    out
}

impl Pack {
    pub fn load() -> Self {
        let passages: Vec<Passage> = GUIDES
            .iter()
            .flat_map(|(guide, source)| passages_of(guide, source))
            .collect();
        let mut terms = Vec::with_capacity(passages.len());
        let mut lengths = Vec::with_capacity(passages.len());
        let mut in_passages: HashMap<String, f32> = HashMap::new();
        for passage in &passages {
            let mut counts: HashMap<String, f32> = HashMap::new();
            let mut length = 0.0;
            // A heading says what the passage is about: its words count three times.
            let weighted = words(passage.text)
                .map(|w| (w, 1.0))
                .chain(words(passage.heading).map(|w| (w, 3.0)));
            for (word, weight) in weighted {
                *counts.entry(word).or_default() += weight;
                length += weight;
            }
            for word in counts.keys() {
                *in_passages.entry(word.clone()).or_default() += 1.0;
            }
            lengths.push(length);
            terms.push(counts);
        }
        let mean_length = lengths.iter().sum::<f32>() / lengths.len().max(1) as f32;
        Self {
            passages,
            terms,
            lengths,
            in_passages,
            mean_length,
        }
    }

    /// The passages that answer `question`, best first, at most `limit`.
    /// A passage counts only when it holds more than half of the question's
    /// distinct words, so an unrelated question finds nothing.
    pub fn search(&self, question: &str, limit: usize) -> Vec<&Passage> {
        let asked: HashSet<String> = words(question).collect();
        if asked.is_empty() {
            return Vec::new();
        }
        let total = self.passages.len() as f32;
        let mut scored: Vec<(f32, usize)> = Vec::new();
        for (i, counts) in self.terms.iter().enumerate() {
            let held = asked.iter().filter(|w| counts.contains_key(*w)).count();
            if held * 2 <= asked.len() {
                continue;
            }
            let score: f32 = asked
                .iter()
                .filter_map(|w| counts.get(w).map(|tf| (w, *tf)))
                .map(|(w, tf)| {
                    let df = self.in_passages[w];
                    let idf = ((total - df + 0.5) / (df + 0.5) + 1.0).ln();
                    idf * tf * (K1 + 1.0)
                        / (tf + K1 * (1.0 - B + B * self.lengths[i] / self.mean_length))
                })
                .sum();
            scored.push((score, i));
        }
        scored.sort_by(|a, b| b.0.total_cmp(&a.0));
        scored
            .into_iter()
            .take(limit)
            .map(|(_, i)| &self.passages[i])
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_guide_yields_passages_with_headings() {
        let pack = Pack::load();
        for (guide, _) in GUIDES {
            assert!(
                pack.passages.iter().any(|p| p.guide == *guide),
                "{guide} has no passage"
            );
        }
        assert!(
            pack.passages
                .iter()
                .all(|p| !p.heading.is_empty() && !p.heading.starts_with('#'))
        );
        assert!(pack.passages.len() > 100);
    }

    #[test]
    fn a_heading_inside_a_code_fence_does_not_cut() {
        let source = "# Title\nintro\n## One\ntext\n```sh\n## not a heading\nrun\n```\nmore\n### Two\nlast\n";
        let cut = passages_of("docs/x.md", source);
        let headings: Vec<_> = cut.iter().map(|p| p.heading).collect();
        assert_eq!(headings, ["Title", "One", "Two"]);
        assert!(cut[1].text.contains("## not a heading") && cut[1].text.ends_with("more"));
    }

    #[test]
    fn an_install_question_is_answered_from_the_install_guides() {
        let pack = Pack::load();
        let found = pack.search("How do I install on Windows?", 3);
        assert!(!found.is_empty());
        let top = found[0];
        assert!(
            top.guide == "docs/INSTALL.md" || top.guide == "docs/GETTING-STARTED.md",
            "top passage is {}",
            top.citation()
        );
        assert!(top.citation().contains(" § "));
    }

    #[test]
    fn a_question_the_guides_do_not_cover_finds_nothing() {
        let pack = Pack::load();
        assert!(pack.search("recipe for sourdough focaccia", 3).is_empty());
        assert!(pack.search("how what the", 3).is_empty());
        assert!(pack.search("", 3).is_empty());
    }
}
