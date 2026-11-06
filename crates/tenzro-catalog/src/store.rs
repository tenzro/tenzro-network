//! The catalog this process serves from.
//!
//! The catalog is data. A node assembles it from the signed entries its
//! operator's trusted publishers have published and installs it here; it is
//! replaced whole, atomically, whenever that set changes, so a newly
//! published model is served without a rebuild or a restart. A client
//! installs the catalog a node returns. Nothing is compiled in: before an
//! install the catalog is empty.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, LazyLock, RwLock};

use crate::entry::{CatalogEntry, Component, EntryError};

/// A validated set of entries, indexed by id and by file.
#[derive(Debug, Default)]
pub struct Catalog {
    entries: Vec<CatalogEntry>,
    by_id: HashMap<String, usize>,
    by_file: HashMap<(String, String), usize>,
}

impl Catalog {
    /// Validate `entries` into a catalog. An entry that is malformed, repeats
    /// an id, or hashes a file differently from another entry is left out and
    /// returned with the reason; a conflict leaves out every entry involved,
    /// since nothing says which of them is right.
    pub fn build(entries: impl IntoIterator<Item = CatalogEntry>) -> (Catalog, Vec<EntryError>) {
        let mut errors = Vec::new();
        let mut valid: BTreeMap<String, CatalogEntry> = BTreeMap::new();
        let mut repeated = BTreeSet::new();
        for e in entries {
            if let Err(err) = e.validate() {
                errors.push(err);
                continue;
            }
            let id = e.id().to_string();
            if valid.contains_key(&id) || repeated.contains(&id) {
                repeated.insert(id);
                continue;
            }
            valid.insert(id, e);
        }
        for id in &repeated {
            valid.remove(id);
            errors.push(EntryError {
                id: id.clone(),
                reason: "the id is listed more than once".into(),
            });
        }

        let mut claims: HashMap<(String, String), Vec<(&str, &Component)>> = HashMap::new();
        for (id, e) in &valid {
            for c in &e.components {
                claims
                    .entry((c.repo.clone(), c.path.clone()))
                    .or_default()
                    .push((id, c));
            }
        }
        let mut conflicted: BTreeMap<String, String> = BTreeMap::new();
        for ((repo, path), owners) in &claims {
            let first = owners[0].1;
            if owners
                .iter()
                .any(|(_, c)| c.sha256 != first.sha256 || c.size != first.size)
            {
                let ids: Vec<&str> = owners.iter().map(|(id, _)| *id).collect();
                for id in &ids {
                    conflicted.entry(id.to_string()).or_insert_with(|| {
                        format!("{repo}/{path} is hashed differently by {}", ids.join(", "))
                    });
                }
            }
        }
        for (id, reason) in conflicted {
            valid.remove(&id);
            errors.push(EntryError { id, reason });
        }
        let missing: Vec<(String, String)> = valid
            .iter()
            .filter_map(|(id, e)| {
                e.requires
                    .iter()
                    .find(|d| !valid.contains_key(&d.entry))
                    .map(|d| {
                        (
                            id.clone(),
                            format!("it requires {}, which is not in the catalog", d.entry),
                        )
                    })
            })
            .collect();
        for (id, reason) in missing {
            valid.remove(&id);
            errors.push(EntryError { id, reason });
        }

        let mut catalog = Catalog::default();
        for (id, e) in valid {
            let at = catalog.entries.len();
            for c in &e.components {
                catalog
                    .by_file
                    .entry((c.repo.clone(), c.path.clone()))
                    .or_insert(at);
            }
            catalog.by_id.insert(id, at);
            catalog.entries.push(e);
        }
        (catalog, errors)
    }

    /// Every entry, in id order.
    pub fn entries(&self) -> &[CatalogEntry] {
        &self.entries
    }

    pub fn entry(&self, id: &str) -> Option<&CatalogEntry> {
        self.by_id.get(id).map(|i| &self.entries[*i])
    }

    /// The entry that lists `repo`/`path` and its component for the file.
    pub fn file(&self, repo: &str, path: &str) -> Option<(&CatalogEntry, &Component)> {
        let e = &self.entries[*self.by_file.get(&(repo.to_string(), path.to_string()))?];
        e.component(repo, path).map(|c| (e, c))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

static CURRENT: LazyLock<RwLock<Arc<Catalog>>> =
    LazyLock::new(|| RwLock::new(Arc::new(Catalog::default())));

/// Replace the catalog this process serves from.
pub fn install(catalog: Catalog) {
    let next = Arc::new(catalog);
    match CURRENT.write() {
        Ok(mut g) => *g = next,
        Err(poisoned) => *poisoned.into_inner() = next,
    }
}

/// The catalog as it is now. Holding the returned value keeps one consistent
/// view even if a new catalog is installed meanwhile.
pub fn current() -> Arc<Catalog> {
    match CURRENT.read() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}
