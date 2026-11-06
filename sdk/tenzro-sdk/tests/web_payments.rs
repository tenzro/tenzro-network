//! The publisher gate and the agent's voucher payer, against a facilitator
//! that keeps voucher accounting the way the ledger does.

use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use tenzro_sdk::error::SdkResult;
use tenzro_sdk::web::*;
use tower::{Layer, Service, ServiceExt};

const PAY_TO: &str = "0909090909090909090909090909090909090909090909090909090909090909";
const CHANNEL: &str = "abababababababababababababababababababababababababababababababab";

#[derive(Default)]
struct Ledger {
    settles: usize,
    highest: u128,
    spent: u128,
}

struct Fac(Mutex<Ledger>);

impl Facilitator for Fac {
    fn settle(&self, body: String) -> BoxFuture<'_, SdkResult<SettlementResponse>> {
        Box::pin(async move {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            let cred = &v["paymentPayload"]["payload"];
            let cumulative: u128 = cred["extra"]["cumulative_amount"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let charge: u128 = v["paymentRequirements"]["amount"]
                .as_str()
                .unwrap()
                .parse()
                .unwrap();
            let mut l = self.0.lock().unwrap();
            l.settles += 1;
            let ok = cumulative >= l.highest && l.spent + charge <= cumulative;
            if ok {
                l.highest = cumulative;
                l.spent += charge;
            }
            Ok(SettlementResponse {
                success: ok,
                error_reason: (!ok).then(|| "invalid_payload".into()),
                payer: None,
                transaction: format!("escrow:{CHANNEL}:{cumulative}"),
                network: "tenzro:1337".into(),
                amount: Some(charge.to_string()),
            })
        })
    }
}

struct Voucher(Mutex<u128>);

impl Payer for Voucher {
    fn supports(&self, r: &PaymentRequirement) -> bool {
        r.scheme == "batch-settlement"
    }
    fn pay<'a>(
        &'a self,
        r: &'a PaymentRequirement,
        _: &'a ResourceInfo,
    ) -> BoxFuture<'a, SdkResult<String>> {
        Box::pin(async move {
            let charge: u128 = r.amount.parse().unwrap();
            let mut c = self.0.lock().unwrap();
            *c += charge;
            let v = SignedAgentVoucher {
                signature: serde_json::json!({ "classical": { "form": "raw", "signature": "11".repeat(64) } }),
                agent: AgentVoucherSigner {
                    agent_did: "did:tenzro:agent:a".into(),
                    machine_did: "did:tenzro:machine:m".into(),
                    as_of_ms: 1,
                },
            };
            agent_voucher_credential(r, CHANNEL, *c, charge, &v, "id")
        })
    }
}

fn policy() -> PublisherPolicy {
    PublisherPolicy {
        chain_id: 1337,
        pay_to: PAY_TO.into(),
        facilitator: "https://facilitator.example".into(),
        routes: vec![PaidRoute {
            path: "/articles/*".into(),
            usd_e6: 2_000,
            permits: vec!["ai-input".into()],
            prohibits: vec!["ai-train".into()],
            content_usage: Some("train-ai=n".into()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn gate() -> (Arc<PublisherGate>, Arc<Fac>) {
    let fac = Arc::new(Fac(Mutex::new(Ledger::default())));
    let quote: Quote = Arc::new(|usd| Box::pin(async move { Ok(u128::from(usd) * 1000) }));
    (
        Arc::new(PublisherGate::new(policy(), fac.clone(), Some(quote))),
        fac,
    )
}

fn signed() -> http::HeaderMap {
    let mut h = http::HeaderMap::new();
    h.insert("signature-input", "sig1=(\"@authority\")".parse().unwrap());
    h.insert("signature", "sig1=:AAAA:".parse().unwrap());
    h
}

const URL: &str = "https://pub.example/articles/1";

async fn required(g: &PublisherGate) -> PaymentRequired {
    match g.decide(URL, &signed()).await {
        GateDecision::PaymentRequired { header, .. } => {
            serde_json::from_str(&decode_header(&header).unwrap()).unwrap()
        }
        other => panic!("expected 402, got {other:?}"),
    }
}

#[tokio::test]
async fn people_browse_free_and_agents_are_asked_to_pay() {
    let (g, fac) = gate();
    assert_eq!(
        g.decide(URL, &http::HeaderMap::new()).await,
        GateDecision::Serve {
            content_usage: Some("train-ai=n".into())
        }
    );
    assert_eq!(
        g.decide("https://pub.example/about", &signed()).await,
        GateDecision::Serve {
            content_usage: None
        }
    );
    let r = required(&g).await;
    assert_eq!(
        r.accepts
            .iter()
            .map(|a| a.scheme.as_str())
            .collect::<Vec<_>>(),
        DEFAULT_SCHEMES
    );
    assert!(
        r.accepts
            .iter()
            .all(|a| a.amount == "2000000" && a.network == "tenzro:1337" && a.pay_to == PAY_TO)
    );
    assert_eq!(fac.0.lock().unwrap().settles, 0);
}

#[tokio::test]
async fn ten_thousand_sub_cent_requests_ride_one_channel_and_a_replay_pays_nothing() {
    let (g, fac) = gate();
    let r = required(&g).await;
    let payer = Voucher(Mutex::new(0));
    let mut last = None;
    for i in 0..10_000 {
        let mut req = r.accepts[0].clone();
        req.extra
            .insert("challengeId".into(), format!("c{i}").into());
        let header = payment_header(&payer, &r, &req).await.unwrap();
        let mut h = signed();
        h.insert(PAYMENT_SIGNATURE_HEADER, header.parse().unwrap());
        assert!(
            matches!(g.decide(URL, &h).await, GateDecision::Paid { .. }),
            "request {i}"
        );
        last = Some(h);
    }
    {
        let l = fac.0.lock().unwrap();
        assert_eq!(l.settles, 10_000);
        assert_eq!(l.highest, 10_000 * 2_000_000);
        assert_eq!(l.spent, l.highest);
    }
    assert!(matches!(
        g.decide(URL, &last.unwrap()).await,
        GateDecision::PaymentRequired { .. }
    ));
}

#[tokio::test]
async fn the_layer_never_runs_the_handler_unpaid() {
    let (g, _) = gate();
    let served = Arc::new(Mutex::new(0usize));
    let s = served.clone();
    let inner = tower::service_fn(move |_req: http::Request<String>| {
        let s = s.clone();
        async move {
            *s.lock().unwrap() += 1;
            Ok::<_, std::convert::Infallible>(http::Response::new("the article".to_string()))
        }
    });
    let mut svc = PublisherGateLayer::new(g.clone()).layer(inner);
    let mut req = http::Request::builder()
        .uri("/articles/1")
        .header("host", "pub.example");
    for (k, v) in signed().iter() {
        req = req.header(k, v);
    }
    let res = svc
        .ready()
        .await
        .unwrap()
        .call(req.body(String::new()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), http::StatusCode::PAYMENT_REQUIRED);
    assert!(res.headers().contains_key(PAYMENT_REQUIRED_HEADER));
    assert_eq!(*served.lock().unwrap(), 0);
    let free = http::Request::builder()
        .uri("/articles/1")
        .header("host", "pub.example")
        .body(String::new())
        .unwrap();
    let res = svc.ready().await.unwrap().call(free).await.unwrap();
    assert_eq!(res.status(), http::StatusCode::OK);
    assert_eq!(res.headers().get("content-usage").unwrap(), "train-ai=n");
    assert_eq!(*served.lock().unwrap(), 1);
}

#[test]
fn the_licence_document_and_robots_line() {
    let xml = rsl_xml(&policy(), "https://pub.example/");
    assert!(xml.contains("<content url=\"https://pub.example/articles/*\">"));
    assert!(xml.contains("<prohibits type=\"usage\">ai-train</prohibits>"));
    assert!(xml.contains("<amount currency=\"USD\">0.002</amount>"));
    assert_eq!(
        robots_license_line("https://pub.example/"),
        "License: https://pub.example/license.xml"
    );
}

#[tokio::test]
async fn the_agent_voucher_payload_matches_the_shared_vector() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../fixtures/payments/x402_agent_voucher.json"
    ))
    .unwrap();
    let r: PaymentRequirement = serde_json::from_value(v["requirement"].clone()).unwrap();
    let voucher: SignedAgentVoucher = serde_json::from_value(v["voucher"].clone()).unwrap();
    let cred = agent_voucher_credential(
        &r,
        v["channel_id"].as_str().unwrap(),
        v["cumulative_amount"].as_str().unwrap().parse().unwrap(),
        r.amount.parse().unwrap(),
        &voucher,
        v["credential_id"].as_str().unwrap(),
    )
    .unwrap();
    assert!(cred.contains("\"amount\":90071992547409930,"));
    struct Fixed(String);
    impl Payer for Fixed {
        fn supports(&self, _: &PaymentRequirement) -> bool {
            true
        }
        fn pay<'a>(
            &'a self,
            _: &'a PaymentRequirement,
            _: &'a ResourceInfo,
        ) -> BoxFuture<'a, SdkResult<String>> {
            Box::pin(async move { Ok(self.0.clone()) })
        }
    }
    let required = PaymentRequired {
        x402_version: 2,
        error: None,
        resource: serde_json::from_value(v["resource"].clone()).unwrap(),
        accepts: vec![r.clone()],
    };
    let ours = payment_header(&Fixed(cred), &required, &r).await.unwrap();
    let parse =
        |h: &str| serde_json::from_str::<serde_json::Value>(&decode_header(h).unwrap()).unwrap();
    assert_eq!(
        parse(&ours),
        parse(v["payment_signature"].as_str().unwrap())
    );
}

// ------------------------------------------------ the shared gate vectors

fn gate_vectors() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures/payments/x402_gate.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// Answers /settle as the case scripts it and records every body.
struct Scripted {
    script: serde_json::Value,
    bodies: Mutex<Vec<String>>,
}

impl Facilitator for Scripted {
    fn settle(&self, body: String) -> BoxFuture<'_, SdkResult<SettlementResponse>> {
        Box::pin(async move {
            self.bodies.lock().unwrap().push(body);
            if self.script["unreachable"].as_bool() == Some(true) {
                return Err(tenzro_sdk::error::SdkError::ConnectionError(
                    "connection refused".into(),
                ));
            }
            Ok(serde_json::from_value(self.script["respond"].clone()).unwrap())
        })
    }
}

fn normalized(mut v: serde_json::Value) -> serde_json::Value {
    for r in v["accepts"].as_array_mut().into_iter().flatten() {
        r["extra"]["challengeId"] = "CHALLENGE".into();
    }
    v
}

#[tokio::test]
async fn the_gate_decides_every_shared_case() {
    let g = gate_vectors();
    let policy: PublisherPolicy = serde_json::from_value(g["policy"].clone()).unwrap();
    let rate = g["quote_rate"].as_u64().unwrap() as u128;
    let origin = g["origin"].as_str().unwrap().trim_end_matches('/');
    for case in g["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let fac = Arc::new(Scripted {
            script: case["facilitator"].clone(),
            bodies: Mutex::new(Vec::new()),
        });
        let quote: Option<Quote> = (case["quote"].as_bool() != Some(false)).then(|| -> Quote {
            Arc::new(move |usd| Box::pin(async move { Ok(u128::from(usd) * rate) }))
        });
        let gate = PublisherGate::new(policy.clone(), fac.clone(), quote);
        let mut headers = http::HeaderMap::new();
        for (k, v) in case["headers"].as_object().unwrap() {
            headers.insert(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.as_str().unwrap().parse().unwrap(),
            );
        }
        if let Some(text) = case["payment_text"].as_str() {
            headers.insert(
                PAYMENT_SIGNATURE_HEADER,
                encode_header(text).parse().unwrap(),
            );
        }
        let url = format!("{origin}{}", case["path"].as_str().unwrap());
        let e = &case["expect"];
        let (status, served, usage, error, response) = match gate.decide(&url, &headers).await {
            GateDecision::Serve { content_usage } => (200, true, content_usage, None, None),
            GateDecision::Paid {
                payment_response,
                content_usage,
            } => (200, true, content_usage, None, Some(payment_response)),
            GateDecision::PaymentRequired {
                body,
                header,
                content_usage,
            } => {
                assert_eq!(decode_header(&header).unwrap(), body, "{name}");
                let v: serde_json::Value = serde_json::from_str(&body).unwrap();
                if e["error"].is_null() {
                    let want: serde_json::Value =
                        serde_json::from_str(g["required_body"].as_str().unwrap()).unwrap();
                    assert_eq!(normalized(v.clone()), want, "{name}");
                }
                (
                    402,
                    false,
                    content_usage,
                    v["error"].as_str().map(str::to_string),
                    None,
                )
            }
            GateDecision::Unavailable => (503, false, None, None, None),
        };
        assert_eq!(status, e["status"].as_u64().unwrap(), "{name}");
        assert_eq!(served, e["served"].as_bool().unwrap(), "{name}");
        if let Some(want) = e.get("content_usage") {
            assert_eq!(usage.as_deref(), want.as_str(), "{name}");
        }
        if status == 402 {
            assert_eq!(error.as_deref(), e["error"].as_str(), "{name}");
        }
        let bodies = fac.bodies.lock().unwrap();
        assert!(bodies.len() <= 1, "{name}");
        assert_eq!(
            bodies.first().map(String::as_str),
            e["settled"].as_str(),
            "{name}"
        );
        if let Some(want) = e["payment_response"].as_str() {
            assert_eq!(decode_header(&response.unwrap()).unwrap(), want, "{name}");
        }
    }
}

#[test]
fn the_licence_document_and_route_matching_match_the_shared_vectors() {
    let g = gate_vectors();
    let policy: PublisherPolicy = serde_json::from_value(g["policy"].clone()).unwrap();
    let origin = g["origin"].as_str().unwrap();
    assert_eq!(rsl_xml(&policy, origin), g["rsl_xml"].as_str().unwrap());
    assert_eq!(
        robots_license_line(origin),
        g["robots_line"].as_str().unwrap()
    );
    for m in g["matches"].as_array().unwrap() {
        let got = match_route(&policy.routes, m[0].as_str().unwrap()).map(|r| r.path.as_str());
        assert_eq!(got, m[1].as_str(), "{}", m[0]);
    }
}
