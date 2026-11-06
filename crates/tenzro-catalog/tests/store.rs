//! The runtime catalog: what is installed is what is served, a malformed or
//! conflicting entry is refused with its reason, and an install replaces the
//! catalog without a restart.

use tenzro_catalog::*;

fn gguf(id: &str, repo: &str, file: &str, sha: char) -> CatalogEntry {
    CatalogEntry {
        model: ModelSpec::Gguf(HfModelEntry {
            id: id.into(),
            name: id.into(),
            family: "test".into(),
            hf_repo: repo.into(),
            hf_filename: file.into(),
            parameters: "1B".into(),
            context_length: 4096,
            quantization: "Q4_K_M".into(),
            size_bytes: 10,
            min_ram_gb: 1,
            promotable: true,
            ..Default::default()
        }),
        licence: Licence {
            name: "Apache-2.0".into(),
            id: None,
            tier: LicenseTier::Permissive,
            conditions: None,
            components: Vec::new(),
        },
        gated: false,
        components: vec![Component {
            repo: repo.into(),
            path: file.into(),
            source: Source::Hub {
                revision: "a".repeat(40),
            },
            size: 10,
            sha256: sha.to_string().repeat(64),
            at: None,
        }],
        capabilities: vec![],
        capability_priors: Default::default(),
        moe_source: None,
        requires: Vec::new(),
    }
}

#[test]
fn an_installed_catalog_is_served_and_a_new_install_replaces_it() {
    let (catalog, errors) = Catalog::build([gguf("m-one", "o/r", "one.gguf", 'a')]);
    assert!(errors.is_empty());
    store::install(catalog);
    assert!(get_model_by_id("m-one").is_some());
    assert!(get_model_by_id("m-two").is_none());

    let (catalog, _) = Catalog::build([
        gguf("m-one", "o/r", "one.gguf", 'a'),
        gguf("m-two", "o/r", "two.gguf", 'b'),
    ]);
    store::install(catalog);
    assert!(get_model_by_id("m-two").is_some());
    let (e, c) = file("o/r", "two.gguf").expect("the new entry's file is known");
    assert_eq!(e.id(), "m-two");
    assert_eq!(c.sha256, "b".repeat(64));

    store::install(Catalog::build([]).0);
    assert!(get_model_catalog().is_empty());
    assert!(file("o/r", "two.gguf").is_none());
}

#[test]
fn a_downloaded_file_without_a_hash_is_refused() {
    let mut e = gguf("m-nohash", "o/r", "w.gguf", 'a');
    e.components.clear();
    let (catalog, errors) = Catalog::build([e]);
    assert!(catalog.is_empty());
    assert!(errors[0].reason.contains("has no hash"), "{errors:?}");
}

#[test]
fn two_entries_hashing_one_file_differently_are_both_refused() {
    let (catalog, errors) = Catalog::build([
        gguf("m-a", "o/r", "same.gguf", 'a'),
        gguf("m-b", "o/r", "same.gguf", 'b'),
        gguf("m-c", "o/r", "other.gguf", 'c'),
    ]);
    assert_eq!(catalog.len(), 1);
    assert!(catalog.entry("m-c").is_some());
    let refused: Vec<&str> = errors.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(refused, ["m-a", "m-b"]);
}

#[test]
fn a_repeated_id_is_refused_rather_than_one_copy_chosen() {
    let (catalog, errors) = Catalog::build([
        gguf("m-x", "o/r", "a.gguf", 'a'),
        gguf("m-x", "o/r", "b.gguf", 'b'),
    ]);
    assert!(catalog.is_empty());
    assert_eq!(errors.len(), 1);
}

#[test]
fn malformed_entries_are_refused_with_the_reason() {
    let mut bad_hash = gguf("m-h", "o/r", "h.gguf", 'a');
    bad_hash.components[0].sha256 = "XYZ".into();
    let mut moving = gguf("m-r", "o/r", "r.gguf", 'a');
    moving.components[0].source = Source::Hub {
        revision: "main".into(),
    };
    let mut escape = gguf("m-p", "o/r", "../p.gguf", 'a');
    escape.components[0].path = "../p.gguf".into();
    let mut custom = gguf("m-l", "o/r", "l.gguf", 'a');
    custom.licence.tier = LicenseTier::CommercialCustom;
    let (catalog, errors) = Catalog::build([
        bad_hash,
        moving,
        escape,
        custom,
        gguf("Bad Id", "o/r", "i.gguf", 'a'),
    ]);
    assert!(catalog.is_empty());
    assert_eq!(errors.len(), 5, "{errors:?}");
}

#[test]
fn a_gated_entry_is_bound_by_its_licence_id() {
    let mut e = gguf("m-g", "o/r", "g.gguf", 'a');
    e.licence.id = Some("custom-terms".into());
    assert_eq!(e.gating_licence(), None);
    e.gated = true;
    assert_eq!(e.gating_licence(), Some("custom-terms"));
    assert!(e.validate().is_ok());
    e.licence.id = None;
    assert!(
        e.validate().is_err(),
        "a gated entry must name the licence operators accept"
    );
}

#[test]
fn an_entry_round_trips_through_json() {
    let e = gguf("m-j", "o/r", "j.gguf", 'a');
    let v = serde_json::to_value(&e).unwrap();
    assert_eq!(v["model"]["engine"], "gguf");
    let back: CatalogEntry = serde_json::from_value(v).unwrap();
    assert_eq!(back.id(), "m-j");
    back.validate().unwrap();
}

/// A network component: no hub copy, fetched by its BLAKE3 content address.
fn network(id: &str, file: &str, blake3: &str) -> CatalogEntry {
    let mut e = gguf(id, "tenzro/built", file, 'b');
    e.components[0].source = Source::Network {
        blake3: blake3.into(),
        built_from: SourceCheckpoint {
            repo: "o/upstream".into(),
            revision: "c".repeat(40),
        },
        recipe: "tools/build/convert.sh".into(),
    };
    e
}

#[test]
fn a_network_component_is_addressed_by_its_content_hash() {
    let e = network("m-n", "n.gguf", &"d".repeat(64));
    e.validate().unwrap();
    let c = &e.components[0];
    assert_eq!(c.network_blake3(), Some("d".repeat(64).as_str()));
    assert_eq!(c.revision(), None);
    let v = serde_json::to_value(&e).unwrap();
    let file = &v["components"][0];
    assert_eq!(file["blake3"], "d".repeat(64));
    assert_eq!(file["built_from"]["revision"], "c".repeat(40));
    assert!(file.get("revision").is_none());
    let back: CatalogEntry = serde_json::from_value(v).unwrap();
    assert_eq!(back.components[0], *c);
    let (catalog, errors) = Catalog::build([e]);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(catalog.len(), 1);
}

#[test]
fn a_network_component_needs_its_address_build_source_and_recipe() {
    let bad_address = network("m-a", "a.gguf", "not-a-hash");
    let mut no_commit = network("m-c", "c.gguf", &"d".repeat(64));
    if let Source::Network { built_from, .. } = &mut no_commit.components[0].source {
        built_from.revision = "main".into();
    }
    let mut no_recipe = network("m-r", "r.gguf", &"d".repeat(64));
    if let Source::Network { recipe, .. } = &mut no_recipe.components[0].source {
        *recipe = "../escape.sh".into();
    }
    // Gated without a licence id for operators to accept.
    let mut gated = network("m-g", "g.gguf", &"d".repeat(64));
    gated.gated = true;
    gated.licence.id = None;
    let (catalog, errors) = Catalog::build([bad_address, no_commit, no_recipe, gated]);
    assert!(catalog.is_empty());
    assert_eq!(errors.len(), 4, "{errors:?}");
}

#[test]
fn a_component_naming_both_a_commit_and_a_content_address_is_refused() {
    let e = network("m-b", "b.gguf", &"d".repeat(64));
    let mut v = serde_json::to_value(&e).unwrap();
    v["components"][0]["revision"] = serde_json::json!("a".repeat(40));
    assert!(serde_json::from_value::<CatalogEntry>(v).is_err());
}

#[test]
fn a_dependency_loads_named_parts_of_another_entry_and_must_resolve() {
    let mut base = gguf("m-base", "o/base", "text_encoder/model.safetensors", 'e');
    base.components.push(Component {
        repo: "o/base".into(),
        path: "transformer/model.safetensors".into(),
        source: Source::Hub {
            revision: "a".repeat(40),
        },
        size: 10,
        sha256: "f".repeat(64),
        at: None,
    });
    let mut world = gguf("m-world", "o/world", "world.safetensors", 'c');
    world.requires = vec![EntryDependency {
        entry: "m-base".into(),
        parts: vec!["text_encoder".into()],
    }];
    world.validate().unwrap();
    let files: Vec<&str> = world
        .required_components(&base)
        .iter()
        .map(|c| c.path.as_str())
        .collect();
    assert_eq!(files, ["text_encoder/model.safetensors"]);

    let (alone, errors) = Catalog::build([world.clone()]);
    assert_eq!(alone.len(), 0);
    assert!(errors[0].reason.contains("requires m-base"), "{errors:?}");
    let (both, errors) = Catalog::build([world.clone(), base]);
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(both.len(), 2);

    world.requires[0].parts = vec!["../x".into()];
    assert!(world.validate().is_err());
}
