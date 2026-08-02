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

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Create a payment gateway with protocols
    let gateway = Arc::new(TenzroPaymentGateway::new());

    // In production, register real payment protocols:
    // #[cfg(feature = "mpp")]
    // {
    //     use tenzro_payments::mpp::MppPaymentServer;
    //     let mpp_server = MppPaymentServer::new(gateway.challenge_store());
    //     gateway.register_protocol(Arc::new(mpp_server));
    // }
    //
    // #[cfg(feature = "x402")]
    // {
    //     use tenzro_payments::x402::X402PaymentServer;
    //     let x402_server = X402PaymentServer::new(gateway.challenge_store());
    //     gateway.register_protocol(Arc::new(x402_server));
    // }

    // Configure the payment gate
    let config = PaymentGateConfig {
        default_amount: 1000, // 1000 units (e.g., 0.001 USDC with 6 decimals)
        default_asset: "USDC".to_string(),
        recipient: "did:tenzro:human:platform".to_string(),
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
