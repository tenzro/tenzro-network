//! Live end-to-end check that per-family embedding instruction templates
//! actually change what gets embedded, using a real downloaded ONNX model.
//!
//! `#[ignore]`d by default: this downloads ~2.4GB from the HF CDN and runs
//! real ONNX inference. Run explicitly with:
//!
//!   cargo test -p tenzro-model --test embedding_template_live -- --ignored --nocapture
//!
//! Deliberately bypasses the node/RPC/genesis machinery entirely — this
//! exercises `TextEmbeddingRuntime` directly, the same code path
//! `download_and_load_text_embedding` in tenzro-node's rpc.rs drives, minus
//! everything that isn't the embedding logic itself.

use tenzro_model::{
    ArtifactSpec, DownloadProgress, DownloadState, EmbedRole, HfArtifactDownloader, SourcePolicy,
    TextEmbedConfig, TextEmbeddingRuntime, TextEncoderFamily, get_text_embedding_model_by_id,
};

#[tokio::test]
#[ignore]
async fn qwen3_embedding_query_and_document_produce_different_vectors() {
    let entry = get_text_embedding_model_by_id("qwen3-embedding-0.6b")
        .expect("qwen3-embedding-0.6b must be in the catalog");

    let tmp = tempfile::tempdir().expect("tmpdir");
    let downloader = HfArtifactDownloader::new(tmp.path().to_path_buf());

    let mut files = vec![entry.hf_filename.clone()];
    if !entry.external_data_filename.is_empty() {
        files.push(entry.external_data_filename.clone());
    }
    files.push(entry.tokenizer_filename.clone());

    let spec = ArtifactSpec::Bundle {
        files,
        dir_name: format!("{}-bundle", entry.id),
        peer_hints: vec![None, None, None],
    };

    let (tx, _rx) = tokio::sync::watch::channel(DownloadProgress {
        model_id: entry.id.clone(),
        status: DownloadState::Pending,
        progress_percent: 0.0,
        downloaded_bytes: 0,
        total_bytes: entry.size_bytes,
    });
    let bundle_dir = downloader
        .download(
            &entry.id,
            &entry.hf_repo,
            &spec,
            entry.size_bytes,
            SourcePolicy::HuggingFace,
            tx,
        )
        .await
        .expect("download qwen3-embedding-0.6b ONNX bundle");

    let onnx_path = bundle_dir.join(&entry.hf_filename);
    let tokenizer_path = bundle_dir.join(&entry.tokenizer_filename);
    assert_eq!(
        entry.family, "qwen3-embedding",
        "this test hardcodes the Qwen3 pooling family — update if the catalog entry changes"
    );

    let runtime = TextEmbeddingRuntime::new();
    runtime
        .load_onnx(
            entry.id.clone(),
            onnx_path,
            tokenizer_path,
            TextEncoderFamily::Qwen3,
            entry.embedding_template.clone(),
            entry.embedding_dim as usize,
            entry.max_sequence_length as usize,
        )
        .expect("load qwen3-embedding-0.6b");

    let text = "What is the boiling point of water at sea level?".to_string();

    let doc_cfg = TextEmbedConfig {
        requested_dim: None,
        normalize: true,
        role: EmbedRole::Document { title: None },
    };
    let query_cfg = TextEmbedConfig {
        requested_dim: None,
        normalize: true,
        role: EmbedRole::Query { task: None },
    };

    let doc_result = runtime
        .embed(&entry.id, vec![text.clone()], doc_cfg)
        .await
        .expect("embed as document");
    let query_result = runtime
        .embed(&entry.id, vec![text], query_cfg)
        .await
        .expect("embed as query");

    let doc_vec = &doc_result.embeddings[0];
    let query_vec = &query_result.embeddings[0];

    assert_eq!(doc_vec.len(), entry.embedding_dim as usize);
    assert_eq!(query_vec.len(), entry.embedding_dim as usize);

    // Cosine similarity between the two — both encode the same underlying
    // sentence so this should be high, but the Instruct: prefix on the
    // query side must change the actual encoded tokens, so it must not be
    // ~1.0 (identical vectors). This is the real assertion: the template is
    // actually reaching the tokenizer, not being silently dropped somewhere
    // in the plumbing.
    let dot: f32 = doc_vec
        .iter()
        .zip(query_vec.iter())
        .map(|(a, b)| a * b)
        .sum();
    println!("cosine similarity (document vs query encoding): {dot}");
    println!("doc_vec[0..4]   = {:?}", &doc_vec[..4]);
    println!("query_vec[0..4] = {:?}", &query_vec[..4]);

    assert!(
        dot < 0.999,
        "document and query embeddings are near-identical (cosine={dot}) — \
         the instruction template is not actually reaching the encoder"
    );
}
