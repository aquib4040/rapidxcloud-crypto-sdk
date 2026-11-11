//! aad.rs — Authenticated Additional Data (AAD) Canonical Encoding

pub const PROTOCOL_V1: u8 = 1;
pub const PROTOCOL_V2: u8 = 2;

/// Builds canonical Protocol v1 chunk AAD: "index|total" as UTF-8 bytes.
/// Exactly matches existing browser WebCrypto and legacy Android paths.
pub fn build_chunk_aad_v1(chunk_index: usize, total_chunks: usize) -> Vec<u8> {
    format!("{}|{}", chunk_index, total_chunks).into_bytes()
}

/// Builds strict Protocol v2 chunk AAD binding all cryptographic parameters:
/// "rxc-v2:{file_uuid}:{generation_id}:{chunk_index}:{total_chunks}:{is_final}"
pub fn build_strict_chunk_aad_v2(
    file_uuid: &str,
    generation_id: &str,
    chunk_index: usize,
    total_chunks: usize,
    is_final: bool,
) -> Vec<u8> {
    format!(
        "rxc-v2:{}:{}:{}:{}:{}",
        file_uuid,
        generation_id,
        chunk_index,
        total_chunks,
        if is_final { 1 } else { 0 }
    )
    .into_bytes()
}

/// Builds canonical AAD for metadata payload: "rxc-meta:{file_uuid}:{generation_id}"
pub fn build_metadata_aad(file_uuid: &str, generation_id: &str) -> Vec<u8> {
    format!("rxc-meta:{}:{}", file_uuid, generation_id).into_bytes()
}
