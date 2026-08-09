//! ZeroClaw tool plugin: `solana_program_integrity`.
//!
//! Fingerprints the exact deployed code region of an upgradeable Solana BPF
//! program and optionally verifies it against an expected SHA-256 pin. The
//! plugin is T0/read-only: it never builds, signs, or submits transactions.

pub mod integrity;

#[cfg(target_family = "wasm")]
mod component {
    use std::collections::HashMap;

    use serde::Deserialize;
    use serde_json::{json, Value};

    use crate::integrity::{
        analyze, normalize_sha256, parse_account_response, programdata_address, require_agreement,
        validate_pubkey, IntegrityReport, RpcAccount, RuntimeConfig,
    };
    use exports::zeroclaw::plugin::plugin_info::Guest as PluginInfo;
    use exports::zeroclaw::plugin::tool::{Guest as Tool, ToolResult};
    use zeroclaw::plugin::logging::{
        log_record, LogLevel, PluginAction, PluginEvent, PluginOutcome,
    };

    wit_bindgen::generate!({
        path: "wit/v0",
        world: "tool-plugin",
        features: ["plugins-wit-v0"],
    });

    const PLUGIN_NAME: &str = "solana-program-integrity";
    const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");
    const TOOL_NAME: &str = "solana_program_integrity";

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteArgs {
        program_id: String,
        expected_sha256: Option<String>,
        #[serde(rename = "__config", default)]
        config: HashMap<String, String>,
    }

    struct SolanaProgramIntegrity;

    impl PluginInfo for SolanaProgramIntegrity {
        fn plugin_name() -> String {
            PLUGIN_NAME.to_string()
        }

        fn plugin_version() -> String {
            PLUGIN_VERSION.to_string()
        }
    }

    impl Tool for SolanaProgramIntegrity {
        fn name() -> String {
            TOOL_NAME.to_string()
        }

        fn description() -> String {
            "Read-only Solana program supply-chain check. Fetches an upgradeable BPF program's \
             ProgramData, fingerprints the exact deployed code region with SHA-256, reports \
             deployment slot and upgrade authority, and optionally verifies an expected hash. \
             Operator config can pin a trusted hash and a second RPC endpoint for agreement."
                .to_string()
        }

        fn parameters_schema() -> String {
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "program_id": {
                        "type": "string",
                        "minLength": 32,
                        "maxLength": 44,
                        "description": "Canonical base58 Solana executable program address."
                    },
                    "expected_sha256": {
                        "type": "string",
                        "pattern": "^[0-9A-Fa-f]{64}$",
                        "description": "Optional expected SHA-256 of the on-chain code region. Operator-configured trusted_sha256 takes precedence."
                    }
                },
                "required": ["program_id"]
            })
            .to_string()
        }

        fn execute(args: String) -> Result<ToolResult, String> {
            match execute_inner(&args) {
                Ok(report) => {
                    emit(
                        PluginAction::Complete,
                        PluginOutcome::Success,
                        "program integrity check completed",
                        Some(&report.verdict),
                    );
                    Ok(ToolResult {
                        success: true,
                        output: serde_json::to_string(&report)
                            .map_err(|_| "failed to serialize integrity report".to_string())?,
                        error: None,
                    })
                }
                Err(error) => {
                    emit(
                        PluginAction::Fail,
                        PluginOutcome::Failure,
                        "program integrity check failed closed",
                        None,
                    );
                    Ok(ToolResult {
                        success: false,
                        output: String::new(),
                        error: Some(error),
                    })
                }
            }
        }
    }

    fn execute_inner(args: &str) -> Result<IntegrityReport, String> {
        let parsed: ExecuteArgs =
            serde_json::from_str(args).map_err(|_| "invalid tool arguments".to_string())?;

        // Reject injection-shaped / malformed model input before any network call.
        validate_pubkey(&parsed.program_id)?;
        let caller_expected = parsed
            .expected_sha256
            .as_deref()
            .map(normalize_sha256)
            .transpose()?;

        let cfg = RuntimeConfig::from_section(&parsed.config)?;
        let (expected, expected_source) = match cfg.trusted_sha256.as_deref() {
            Some(hash) => (Some(hash), Some("operator_config")),
            None => (
                caller_expected.as_deref(),
                caller_expected.as_ref().map(|_| "caller"),
            ),
        };

        let mut primary = inspect_endpoint(
            &cfg.rpc_url,
            &parsed.program_id,
            cfg.max_program_bytes,
            expected,
            expected_source,
        )?;

        if let Some(secondary_url) = cfg.secondary_rpc_url.as_deref() {
            let secondary = inspect_endpoint(
                secondary_url,
                &parsed.program_id,
                cfg.max_program_bytes,
                expected,
                expected_source,
            )?;
            require_agreement(&primary, &secondary)?;
            primary.rpc_sources = 2;
        }

        Ok(primary)
    }

    fn inspect_endpoint(
        rpc_url: &str,
        program_id: &str,
        max_program_bytes: usize,
        expected_sha256: Option<&str>,
        expected_source: Option<&str>,
    ) -> Result<IntegrityReport, String> {
        let program = fetch_account(rpc_url, program_id, 512)?;
        let programdata_id = programdata_address(&program)?;
        let programdata = fetch_account(
            rpc_url,
            &programdata_id,
            max_program_bytes.saturating_add(45),
        )?;
        analyze(
            program_id,
            &program,
            &programdata,
            expected_sha256,
            expected_source,
        )
    }

    fn fetch_account(rpc_url: &str, address: &str, max_bytes: usize) -> Result<RpcAccount, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [address, {"encoding": "base64", "commitment": "finalized"}]
        });
        let value = post_json(rpc_url, &body)?;
        parse_account_response(&value, max_bytes)
    }

    fn post_json(url: &str, body: &Value) -> Result<Value, String> {
        waki::Client::new()
            .post(url)
            .json(body)
            .send()
            .map_err(|_| "RPC request failed".to_string())?
            .json::<Value>()
            .map_err(|_| "RPC returned invalid JSON".to_string())
    }

    fn emit(action: PluginAction, outcome: PluginOutcome, message: &str, verdict: Option<&str>) {
        let attrs = verdict.map(|value| json!({"verdict": value}).to_string());
        log_record(
            LogLevel::Info,
            &PluginEvent {
                function_name: "solana_program_integrity::tool::execute".to_string(),
                action,
                outcome: Some(outcome),
                duration_ms: None,
                attrs,
                message: message.to_string(),
            },
        );
    }

    export!(SolanaProgramIntegrity);
}
