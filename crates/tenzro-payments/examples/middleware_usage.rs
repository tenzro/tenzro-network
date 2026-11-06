//! Example of using the payment gate middleware with Axum
//!
//! This example demonstrates how to set up payment-gated API endpoints
//! using the Axum middleware layer.

use axum::{Router, routing::get};
use std::sync::Arc;
use tenzro_payments::{
    gateway::TenzroPaymentGateway,
    middleware::{PaymentGateConfig, PaymentGateMiddleware, payment_gate_handler},
};

/// The chain id the network's genesis sets; 13380 is the preview network.
const CHAIN_ID: u64 = 13380;

/// Stands in for the node's reader of the keys accounts enrolled in chain
/// state; here no account has enrolled an ML-DSA-65 key.
struct NoneEnrolled;

impl tenzro_payments::EnrolledKeys for NoneEnrolled {
    fn enrolled_pq_key(&self, _p256_xy: &[u8]) -> tenzro_payments::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

fn keys() -> Arc<dyn tenzro_payments::EnrolledKeys> {
    Arc::new(NoneEnrolled)
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create a payment gateway with protocols
    let gateway = Arc::new(TenzroPaymentGateway::new(CHAIN_ID, keys()));

    // Protocols the gate issues challenges under. A gateway with no rail
    // settles nothing: a node attaches its ledger rail with `with_rail`.
    gateway.register_protocol(Arc::new(
        tenzro_payments::mpp::MppPaymentServer::new(keys())
            .with_challenge_store(gateway.challenge_store()),
    ));
    gateway.register_protocol(Arc::new(
        tenzro_payments::x402::X402PaymentServer::new(CHAIN_ID, vec!["tenzro".to_string()], keys())
            .with_challenge_store(gateway.challenge_store()),
    ));

    // Configure the payment gate
    let config = PaymentGateConfig {
        default_amount: 1000,
        default_asset: "TNZO".to_string(),
        // The payee's Tenzro address (hex).
        recipient: "0909090909090909090909090909090909090909".to_string(),
        default_protocol: "mpp".to_string(),
    };

    // Create the middleware
    let payment_middleware =
        PaymentGateMiddleware::new(gateway.clone(), config, gateway.challenge_store());

    // Build the router with payment-gated endpoints
    let app = Router::new()
        // Free endpoint - no payment required
        .route("/health", get(|| async { "OK" }))
        // Paid endpoints - require payment
        .route("/api/premium", get(premium_handler))
        .route("/api/data", get(data_handler))
        // Apply payment middleware to all /api/* routes
        .layer(axum::middleware::from_fn_with_state(
            payment_middleware,
            payment_gate_handler,
        ));

    println!("Starting server on http://127.0.0.1:3000");
    println!("Try these endpoints:");
    println!("  GET http://127.0.0.1:3000/health (free)");
    println!("  GET http://127.0.0.1:3000/api/premium (paid - will return 402)");
    println!("  GET http://127.0.0.1:3000/api/data (paid - will return 402)");

    // Run the server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Premium API handler - protected by payment middleware
async fn premium_handler() -> &'static str {
    "Premium content"
}

/// Data API handler - protected by payment middleware
async fn data_handler() -> &'static str {
    r#"{"data": "sensitive information"}"#
}
