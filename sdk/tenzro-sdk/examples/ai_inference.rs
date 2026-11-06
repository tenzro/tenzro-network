//! AI Inference example for Tenzro SDK
//!
//! This example demonstrates:
//! - Listing available AI models
//! - Submitting inference requests
//! - Estimating inference costs

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for logging
    tracing_subscriber::fmt::init();

    println!("=== Tenzro SDK AI Inference Example ===\n");

    // The preview network: its staked RPC operators, found on chain
    let client =
        tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default())
            .await?;
    let inference = client.inference();

    // List available models
    println!("Listing available AI models...");
    let models = inference.list_models().await?;
    println!("Found {} models\n", models.len());

    for model in &models {
        println!("Model: {}", model.model_id);
        println!("  Name: {}", model.name);
        println!("  Version: {}", model.version);
        println!("  Description: {}", model.description);
        println!();
    }

    // Estimate what a call would cost on a provider's published card
    let model_id = "gemma4-9b";
    let provider = std::env::var("TENZRO_PROVIDER").unwrap_or_default();
    let mut units = tenzro_sdk::pricing::BillableUnits::new();
    units.set("input_tokens", 100)?;
    units.set("output_tokens", 200)?;
    if !provider.is_empty() {
        let estimated_cost = inference.estimate_cost(&provider, model_id, &units).await?;
        println!("Estimated cost: {} TNZO base units\n", estimated_cost);
    }

    // Submit an inference request
    println!("Submitting inference request...");
    let response = inference
        .request(model_id, "What is the capital of France?", Some(100))
        .await?;

    println!("Inference completed!");
    println!("Model: {}", response.model_id);
    println!("Output: {}", response.output);
    println!("Tokens used: {}", response.tokens_used());
    println!("Cost: {} wei", response.cost_wei);

    println!("\n=== Example completed successfully! ===");

    Ok(())
}
