//! The JSON-RPC 2.0 request envelope every node surface decodes.

use serde::Deserialize;
use serde_json::Value;

/// One JSON-RPC request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC protocol version. Per JSON-RPC 2.0 §4, MUST be the string
    /// `"2.0"`; a request with any other value is refused with -32600
    /// Invalid Request before dispatch.
    pub jsonrpc: String,
    pub method: String,
    pub params: Option<Value>,
    pub id: Value,
}

/// A single positional argument that is itself an object is treated as
/// named params. Other shapes (several positional arguments, or a single
/// non-object one) pass through unchanged for handlers that expect arrays.
pub fn normalize_params(params: Option<Value>) -> Option<Value> {
    match params {
        Some(Value::Array(mut arr)) if arr.len() == 1 => {
            if matches!(arr.first(), Some(Value::Object(_))) {
                Some(arr.remove(0))
            } else {
                Some(Value::Array(arr))
            }
        }
        other => other,
    }
}

/// Every call one JSON-RPC body carries, a single call or a batch, decoded
/// as the endpoints decode it before dispatch: each call's method and
/// normalized params, or why it is refused.
pub fn decode_body(body: &[u8]) -> Vec<Result<(String, Option<Value>), String>> {
    let Ok(payload) = serde_json::from_slice::<Value>(body) else {
        return vec![Err("parse error".to_string())];
    };
    let items = match payload {
        Value::Array(items) => items,
        single => vec![single],
    };
    items
        .into_iter()
        .map(|item| {
            let request = serde_json::from_value::<JsonRpcRequest>(item)
                .map_err(|e| format!("Invalid request: {e}"))?;
            if request.jsonrpc != "2.0" {
                return Err("Invalid Request: jsonrpc field must be \"2.0\"".to_string());
            }
            Ok((request.method, normalize_params(request.params)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_decodes_to_its_calls() {
        let calls = decode_body(
            br#"[{"jsonrpc":"2.0","id":1,"method":"m","params":[{"a":1}]},{"jsonrpc":"1.0","id":2,"method":"n"},7]"#,
        );
        assert_eq!(calls.len(), 3);
        let (method, params) = calls[0].as_ref().unwrap();
        assert_eq!(method, "m");
        assert_eq!(params.as_ref().unwrap()["a"], 1);
        assert!(calls[1].is_err());
        assert!(calls[2].is_err());
        assert!(decode_body(b"{").first().unwrap().is_err());
    }
}
