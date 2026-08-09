use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const UPGRADEABLE_LOADER: &str = "BPFLoaderUpgradeab1e11111111111111111111111";
const PROGRAM_TAG: u32 = 2;
const PROGRAM_DATA_TAG: u32 = 3;
const PROGRAM_DATA_METADATA_LEN: usize = 45;
const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const DEFAULT_MAX_PROGRAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_RPC_URL_LEN: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcAccount {
    pub context_slot: u64,
    pub owner: String,
    pub executable: bool,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub rpc_url: String,
    pub secondary_rpc_url: Option<String>,
    pub trusted_sha256: Option<String>,
    pub max_program_bytes: usize,
}

impl RuntimeConfig {
    pub fn from_section(section: &HashMap<String, String>) -> Result<Self, String> {
        const ALLOWED: [&str; 4] = [
            "rpc_url",
            "secondary_rpc_url",
            "trusted_sha256",
            "max_program_bytes",
        ];
        for key in section.keys() {
            if !ALLOWED.contains(&key.as_str()) {
                return Err(format!("unsupported config key: {key}"));
            }
        }

        let rpc_url = section
            .get("rpc_url")
            .cloned()
            .unwrap_or_else(|| DEFAULT_RPC_URL.to_string());
        validate_rpc_url(&rpc_url)?;

        let secondary_rpc_url = match section.get("secondary_rpc_url") {
            Some(value) if !value.trim().is_empty() => {
                validate_rpc_url(value)?;
                if value == &rpc_url {
                    return Err("secondary_rpc_url must differ from rpc_url".to_string());
                }
                Some(value.clone())
            }
            _ => None,
        };

        let trusted_sha256 = section
            .get("trusted_sha256")
            .map(|value| normalize_sha256(value))
            .transpose()?;

        let max_program_bytes = match section.get("max_program_bytes") {
            Some(value) => value
                .parse::<usize>()
                .map_err(|_| "max_program_bytes must be an integer".to_string())?,
            None => DEFAULT_MAX_PROGRAM_BYTES,
        };
        if !(1024..=DEFAULT_MAX_PROGRAM_BYTES).contains(&max_program_bytes) {
            return Err(format!(
                "max_program_bytes must be between 1024 and {DEFAULT_MAX_PROGRAM_BYTES}"
            ));
        }

        Ok(Self {
            rpc_url,
            secondary_rpc_url,
            trusted_sha256,
            max_program_bytes,
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct IntegrityReport {
    pub verdict: String,
    pub reason: String,
    pub program_id: String,
    pub programdata_address: String,
    pub program_context_slot: u64,
    pub programdata_context_slot: u64,
    pub deployment_slot: u64,
    pub upgrade_authority: Option<String>,
    pub immutable: bool,
    pub code_sha256: String,
    pub code_bytes: usize,
    pub expected_sha256: Option<String>,
    pub expected_source: Option<String>,
    pub hash_match: Option<bool>,
    pub rpc_sources: u8,
}

pub fn validate_pubkey(value: &str) -> Result<[u8; 32], String> {
    if !(32..=44).contains(&value.len()) || !value.is_ascii() {
        return Err("program_id must be a canonical base58 Solana public key".to_string());
    }
    let decoded = bs58::decode(value)
        .into_vec()
        .map_err(|_| "program_id must be valid base58".to_string())?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "program_id must decode to exactly 32 bytes".to_string())?;
    if bs58::encode(bytes).into_string() != value {
        return Err("program_id must use canonical base58 encoding".to_string());
    }
    Ok(bytes)
}

pub fn normalize_sha256(value: &str) -> Result<String, String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected SHA-256 must be exactly 64 hexadecimal characters".to_string());
    }
    Ok(value.to_ascii_lowercase())
}

pub fn validate_rpc_url(value: &str) -> Result<(), String> {
    if value.len() > MAX_RPC_URL_LEN
        || !value.starts_with("https://")
        || value.contains('@')
        || value.contains(char::is_whitespace)
    {
        return Err("RPC URL must be a credential-free HTTPS URL".to_string());
    }
    let host_and_path = &value[8..];
    let host = host_and_path.split('/').next().unwrap_or("");
    if host.is_empty()
        || host.eq_ignore_ascii_case("localhost")
        || host.starts_with("127.")
        || host == "0.0.0.0"
        || host == "[::1]"
    {
        return Err("RPC URL host is not allowed".to_string());
    }
    Ok(())
}

pub fn parse_account_response(
    value: &Value,
    max_decoded_bytes: usize,
) -> Result<RpcAccount, String> {
    if value.get("error").is_some() {
        return Err("RPC returned an error".to_string());
    }
    let result = value
        .get("result")
        .ok_or_else(|| "RPC response is missing result".to_string())?;
    let context_slot = result
        .get("context")
        .and_then(|v| v.get("slot"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "RPC response is missing context slot".to_string())?;
    let account = result
        .get("value")
        .ok_or_else(|| "RPC response is missing account value".to_string())?;
    if account.is_null() {
        return Err("account was not found".to_string());
    }
    let owner = account
        .get("owner")
        .and_then(Value::as_str)
        .ok_or_else(|| "account owner is missing".to_string())?
        .to_string();
    let executable = account
        .get("executable")
        .and_then(Value::as_bool)
        .ok_or_else(|| "account executable flag is missing".to_string())?;
    let encoded = account
        .get("data")
        .and_then(Value::as_array)
        .and_then(|parts| parts.first())
        .and_then(Value::as_str)
        .ok_or_else(|| "account data is not base64".to_string())?;

    let upper_bound = encoded.len().saturating_add(3) / 4 * 3;
    if upper_bound > max_decoded_bytes.saturating_add(2) {
        return Err("account data exceeds configured byte limit".to_string());
    }
    let data = STANDARD
        .decode(encoded)
        .map_err(|_| "account data has invalid base64".to_string())?;
    if data.len() > max_decoded_bytes {
        return Err("account data exceeds configured byte limit".to_string());
    }

    Ok(RpcAccount {
        context_slot,
        owner,
        executable,
        data,
    })
}

pub fn programdata_address(program: &RpcAccount) -> Result<String, String> {
    if program.owner != UPGRADEABLE_LOADER {
        return Err("program is not owned by the upgradeable BPF loader".to_string());
    }
    if !program.executable {
        return Err("program account is not executable".to_string());
    }
    if program.data.len() != 36 {
        return Err("upgradeable program account must contain exactly 36 bytes".to_string());
    }
    if read_u32_le(&program.data[0..4])? != PROGRAM_TAG {
        return Err("account is not an upgradeable-loader Program state".to_string());
    }
    Ok(bs58::encode(&program.data[4..36]).into_string())
}

pub fn analyze(
    program_id: &str,
    program: &RpcAccount,
    programdata: &RpcAccount,
    expected_sha256: Option<&str>,
    expected_source: Option<&str>,
) -> Result<IntegrityReport, String> {
    validate_pubkey(program_id)?;
    let programdata_address = programdata_address(program)?;

    if programdata.owner != UPGRADEABLE_LOADER {
        return Err("ProgramData account has an unexpected owner".to_string());
    }
    if programdata.executable {
        return Err("ProgramData account must not be executable".to_string());
    }
    if programdata.context_slot < program.context_slot {
        return Err("RPC context moved backwards between account reads".to_string());
    }
    if programdata.data.len() <= PROGRAM_DATA_METADATA_LEN {
        return Err("ProgramData account is too short to contain program bytes".to_string());
    }
    if read_u32_le(&programdata.data[0..4])? != PROGRAM_DATA_TAG {
        return Err("account is not an upgradeable-loader ProgramData state".to_string());
    }

    let deployment_slot = read_u64_le(&programdata.data[4..12])?;
    let upgrade_authority = match programdata.data[12] {
        0 => None,
        1 => Some(bs58::encode(&programdata.data[13..45]).into_string()),
        _ => return Err("ProgramData upgrade-authority option is malformed".to_string()),
    };

    let code = &programdata.data[PROGRAM_DATA_METADATA_LEN..];
    if code.len() < 4 || &code[..4] != b"\x7fELF" {
        return Err("ProgramData code region does not begin with ELF magic".to_string());
    }
    let code_sha256 = hex_lower(&Sha256::digest(code));
    let expected = expected_sha256.map(normalize_sha256).transpose()?;
    let hash_match = expected.as_ref().map(|hash| hash == &code_sha256);
    let immutable = upgrade_authority.is_none();

    let (verdict, reason) = match hash_match {
        Some(false) => (
            "RED",
            "deployed program bytes do not match the expected SHA-256 pin",
        ),
        Some(true) if immutable => (
            "GREEN",
            "deployed program bytes match the expected pin and the program is immutable",
        ),
        Some(true) => (
            "AMBER",
            "deployed program bytes match the expected pin, but an upgrade authority can still replace them",
        ),
        None if immutable => (
            "AMBER",
            "program is immutable, but no expected SHA-256 pin was supplied; record the fingerprint before trusting it",
        ),
        None => (
            "AMBER",
            "program is upgradeable and no expected SHA-256 pin was supplied",
        ),
    };

    Ok(IntegrityReport {
        verdict: verdict.to_string(),
        reason: reason.to_string(),
        program_id: program_id.to_string(),
        programdata_address,
        program_context_slot: program.context_slot,
        programdata_context_slot: programdata.context_slot,
        deployment_slot,
        upgrade_authority,
        immutable,
        code_sha256,
        code_bytes: code.len(),
        expected_sha256: expected,
        expected_source: expected_source.map(str::to_string),
        hash_match,
        rpc_sources: 1,
    })
}

pub fn require_agreement(
    primary: &IntegrityReport,
    secondary: &IntegrityReport,
) -> Result<(), String> {
    if primary.program_id != secondary.program_id
        || primary.programdata_address != secondary.programdata_address
        || primary.deployment_slot != secondary.deployment_slot
        || primary.upgrade_authority != secondary.upgrade_authority
        || primary.code_sha256 != secondary.code_sha256
        || primary.code_bytes != secondary.code_bytes
    {
        return Err("configured RPC endpoints disagree on deployed program state".to_string());
    }
    Ok(())
}

fn read_u32_le(bytes: &[u8]) -> Result<u32, String> {
    let array: [u8; 4] = bytes
        .try_into()
        .map_err(|_| "expected four bytes".to_string())?;
    Ok(u32::from_le_bytes(array))
}

fn read_u64_le(bytes: &[u8]) -> Result<u64, String> {
    let array: [u8; 8] = bytes
        .try_into()
        .map_err(|_| "expected eight bytes".to_string())?;
    Ok(u64::from_le_bytes(array))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
