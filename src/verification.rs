use crate::{GetWindowSuccess, Share, Slice};
use alloc::{collections::btree_map::BTreeMap, vec::Vec};
use binary_sv2::{B064K, U256};
use sha2::{Digest, Sha256};

/// Errors that can occur during verification
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationError {
    /// Invalid merkle path provided
    InvalidMerklePath,
    /// Share index out of bounds for the slice
    ShareIndexOutOfBounds,
    /// Share difficulty sum exceeds slice difficulty
    DifficultyExceeded,
    /// Share fees exceed slice reference job fees + delta
    FeesExceeded,
    /// Invalid share hash
    InvalidShareHash,
    /// Slice not found in window
    SliceNotFound,
    /// Invalid previous hash
    InvalidPreviousHash,
    /// Mathematical calculation error
    CalculationError,
}

/// Result type for verification operations
pub type VerificationResult<T> = Result<T, VerificationError>;

/// Detailed result of share verification
#[derive(Debug, Clone, PartialEq)]
pub struct ShareVerificationResult {
    pub share_index: u32,
    pub merkle_valid: bool,
    pub difficulty_valid: bool,
    pub fees_valid: bool,
    pub slice_inclusion_valid: bool,
}

/// Result of slice integrity verification
#[derive(Debug, Clone, PartialEq)]
pub struct SliceVerificationResult {
    pub slice_job_id: u64,
    pub total_shares_valid: bool,
    pub difficulty_sum_valid: bool,
    pub merkle_tree_valid: bool,
    pub share_results: Vec<ShareVerificationResult>,
}

/// Result of PPLNS window verification
#[derive(Debug, Clone, PartialEq)]
pub struct WindowVerificationResult {
    pub window_valid: bool,
    pub total_difficulty: u64,
    pub slice_results: Vec<SliceVerificationResult>,
    pub phash_consistency: bool,
}

/// Configuration for verification tolerances
#[derive(Debug, Clone)]
pub struct VerificationConfig {
    /// Maximum allowed fee delta above slice reference job fees
    pub fee_delta: u64,
    /// Whether to perform strict difficulty checking
    pub strict_difficulty: bool,
    /// Whether to verify all merkle paths or sample
    pub verify_all_merkle_paths: bool,
}

/// Verifies that a share's merkle path correctly leads to the slice root
pub fn verify_merkle_path(share: &Share, slice: &Slice) -> VerificationResult<bool> {
    let share_hash = calculate_share_hash(share)?;

    let calculated_root = compute_merkle_root_from_path(
        &share_hash,
        &share.merkle_path,
        share.share_index,
        slice.number_of_shares,
    )?;

    let slice_root_bytes: [u8; 32] = slice.root.clone().into();
    Ok(calculated_root.as_ref() == &slice_root_bytes)
}

pub fn validate_slice_integrity(
    slice: &Slice,
    shares: &[Share],
    config: &VerificationConfig,
) -> VerificationResult<SliceVerificationResult> {
    let mut share_results = Vec::new();
    let mut total_difficulty = 0u64;

    for share in shares {
        let share_result = verify_share_in_slice(share, slice, config)?;

        if share_result.difficulty_valid {
            total_difficulty += calculate_share_difficulty(share)?;
        }

        share_results.push(share_result);
    }

    let total_shares_valid = shares.len() == slice.number_of_shares as usize;
    let difficulty_sum_valid = if config.strict_difficulty {
        total_difficulty <= slice.difficulty
    } else {
        true
    };

    // Verify merkle tree structure if requested
    let merkle_tree_valid = if config.verify_all_merkle_paths {
        verify_slice_merkle_tree(slice, shares)?
    } else {
        true
    };

    Ok(SliceVerificationResult {
        slice_job_id: slice.job_id,
        total_shares_valid,
        difficulty_sum_valid,
        merkle_tree_valid,
        share_results,
    })
}

/// Verifies a single share against its containing slice
pub fn verify_share_in_slice(
    share: &Share,
    slice: &Slice,
    config: &VerificationConfig,
) -> VerificationResult<ShareVerificationResult> {
    let merkle_valid = verify_merkle_path(share, slice)?;

    let index_valid = share.share_index < slice.number_of_shares;

    let difficulty_valid = verify_share_difficulty(share, slice)?;

    let fees_valid = verify_share_fees(share, slice, config.fee_delta)?;

    let slice_inclusion_valid = share.reference_job_id == slice.job_id;

    Ok(ShareVerificationResult {
        share_index: share.share_index,
        merkle_valid: merkle_valid && index_valid,
        difficulty_valid,
        fees_valid,
        slice_inclusion_valid,
    })
}

/// Verifies that share fees don't exceed slice reference job fees + delta
pub fn verify_share_fees(share: &Share, slice: &Slice, fee_delta: u64) -> VerificationResult<bool> {
    let share_fees = calculate_share_fees(share)?;

    let max_allowed_fees = slice.fees.saturating_add(fee_delta);

    Ok(share_fees <= max_allowed_fees)
}

/// Verifies share difficulty meets requirements
pub fn verify_share_difficulty(share: &Share, slice: &Slice) -> VerificationResult<bool> {
    let share_difficulty = calculate_share_difficulty(share)?;

    // Basic sanity check -share difficulty should be reasonable
    // (specific difficulty requirements depend on pool configuration)
    Ok(share_difficulty > 0 && share_difficulty <= slice.difficulty)
}

/// Verifies PPLNS window consistency with pre-fetched slice data
pub fn verify_pplns_window(
    window: &GetWindowSuccess,
    slice_shares_map: &BTreeMap<u64, Vec<Share>>, // job_id -> shares
    config: &VerificationConfig,
) -> VerificationResult<WindowVerificationResult> {
    let mut slice_results = Vec::new();
    let mut total_difficulty = 0u64;

    for slice in window.slices.clone().into_inner() {
        let empty_shares = Vec::new();
        let shares = slice_shares_map.get(&slice.job_id).unwrap_or(&empty_shares);

        let slice_result = validate_slice_integrity(&slice, shares, config)?;

        if slice_result.difficulty_sum_valid {
            total_difficulty += slice.difficulty;
        }

        slice_results.push(slice_result);
    }

    let phash_consistency = verify_phash_consistency(window)?;

    // Overall window validity
    let window_valid = slice_results
        .iter()
        .all(|r| r.total_shares_valid && r.difficulty_sum_valid && r.merkle_tree_valid)
        && phash_consistency;

    Ok(WindowVerificationResult {
        window_valid,
        total_difficulty,
        slice_results,
        phash_consistency,
    })
}

/// Verifies PPLNS window structure and mathematical consistency (without share data)
pub fn verify_window_structure(window: &GetWindowSuccess) -> VerificationResult<bool> {
    let slices = window.slices.clone().into_inner();

    if slices.is_empty() {
        return Ok(false);
    }

    for (i, slice) in slices.iter().enumerate() {
        if slice.number_of_shares == 0 && slice.difficulty > 0 {
            return Ok(false);
        }

        if slice.difficulty == 0 && slice.number_of_shares > 0 {
            return Ok(false);
        }

        if slice.job_id == 0 {
            return Ok(false);
        }

        for j in (i + 1)..slices.len() {
            if slices[j].job_id == slice.job_id {
                return Ok(false); // Duplicate job_id
            }
        }
    }

    verify_phash_consistency(window)
}

/// Verifies that PHash entries correctly map to slices
pub fn verify_phash_consistency(window: &GetWindowSuccess) -> VerificationResult<bool> {
    let slices = window.slices.clone().into_inner();
    let phashes = window.phashes.clone().into_inner();

    for phash in phashes {
        let start_index = phash.index_start as usize;

        if start_index >= slices.len() {
            return Ok(false);
        }

        // TODO:: Verify that slices after this index use this phash
        // (This would require additional previous hash data in shares)
    }

    Ok(true)
}

/// Calculates the difficulty score for a share in PPLNS-JD
pub fn calculate_difficulty_score(
    share_difficulty: u64,
    total_window_difficulty: u64,
) -> VerificationResult<f64> {
    if total_window_difficulty == 0 {
        return Err(VerificationError::CalculationError);
    }

    Ok(share_difficulty as f64 / total_window_difficulty as f64)
}

/// Calculates the fee-based score for a share within its slice
pub fn calculate_fee_score(
    share: &Share,
    slice: &Slice,
    slice_shares: &[Share],
) -> VerificationResult<f64> {
    let share_fees = calculate_share_fees(share)?;
    let share_difficulty = calculate_share_difficulty(share)?;

    let share_fee_weighted_difficulty = (share_difficulty as f64) * (share_fees as f64);

    let total_fee_weighted_difficulty: f64 = slice_shares
        .iter()
        .map(|s| {
            let fees = calculate_share_fees(s).unwrap_or(0);
            let difficulty = calculate_share_difficulty(s).unwrap_or(0);
            (difficulty as f64) * (fees as f64)
        })
        .sum();

    if total_fee_weighted_difficulty == 0.0 {
        return Err(VerificationError::CalculationError);
    }

    Ok(share_fee_weighted_difficulty / total_fee_weighted_difficulty)
}

/// Calculates the expected payout for a share under PPLNS-JD
/// Returns (subsidy_payout, fee_payout)
/// Calculate difficulty-based score (for subsidy distribution)
pub fn calculate_share_payout(
    share: &Share,
    slice: &Slice,
    slice_shares: &[Share],
    block_subsidy: u64,
    block_fees: u64,
    total_slices: usize,
) -> VerificationResult<(u64, u64)> {
    let total_slice_difficulty: u64 = slice_shares
        .iter()
        .map(|s| calculate_share_difficulty(s).unwrap_or(0))
        .sum();

    let share_difficulty = calculate_share_difficulty(share)?;
    let difficulty_score = if total_slice_difficulty > 0 {
        share_difficulty as f64 / total_slice_difficulty as f64
    } else {
        0.0
    };

    let fee_score = calculate_fee_score(share, slice, slice_shares)?;

    let subsidy_payout = (block_subsidy as f64 * difficulty_score) as u64;
    let slice_fee_allocation = block_fees / total_slices as u64;
    let fee_payout = (slice_fee_allocation as f64 * fee_score) as u64;

    Ok((subsidy_payout, fee_payout))
}

/// Calculates hash of a share for merkle tree verification
fn calculate_share_hash(share: &Share) -> VerificationResult<[u8; 32]> {
    let mut hasher = Sha256::new();

    hasher.update(&share.nonce.to_le_bytes());
    hasher.update(&share.ntime.to_le_bytes());
    hasher.update(&share.version.to_le_bytes());
    hasher.update(share.extranonce.as_ref());
    hasher.update(&share.job_id.to_le_bytes());

    Ok(hasher.finalize().into())
}

/// Computes merkle root from a share hash and its merkle path
fn compute_merkle_root_from_path(
    share_hash: &[u8; 32],
    merkle_path: &B064K,
    share_index: u32,
    total_shares: u32,
) -> VerificationResult<U256<'static>> {
    let path_data = merkle_path.as_ref();
    let mut current_hash = *share_hash;
    let mut index = share_index;

    for i in (0..path_data.len()).step_by(32) {
        if i + 32 > path_data.len() {
            break;
        }

        let sibling_hash: [u8; 32] = path_data[i..i + 32]
            .try_into()
            .map_err(|_| VerificationError::InvalidMerklePath)?;

        let mut hasher = Sha256::new();

        if index % 2 == 0 {
            hasher.update(&current_hash);
            hasher.update(&sibling_hash);
        } else {
            hasher.update(&sibling_hash);
            hasher.update(&current_hash);
        }

        current_hash = hasher.finalize().into();
        index /= 2;
    }

    Ok(current_hash.into())
}

/// Verifies the entire merkle tree structure for a slice
fn verify_slice_merkle_tree(slice: &Slice, shares: &[Share]) -> VerificationResult<bool> {
    if shares.is_empty() {
        return Ok(slice.number_of_shares == 0);
    }

    if shares.len() != slice.number_of_shares as usize {
        return Ok(false);
    }

    let mut share_hashes = Vec::new();
    for share in shares {
        let share_hash = calculate_share_hash(share)?;
        share_hashes.push(share_hash);
    }

    let calculated_root = build_merkle_tree(&share_hashes)?;

    // Convert slice root to [u8; 32] for comparison
    let slice_root_bytes: [u8; 32] = slice.root.clone().into();

    Ok(calculated_root == slice_root_bytes)
}

/// Builds a merkle tree from leaf hashes and returns the root
fn build_merkle_tree(leaf_hashes: &[[u8; 32]]) -> VerificationResult<[u8; 32]> {
    if leaf_hashes.is_empty() {
        return Err(VerificationError::InvalidMerklePath);
    }

    if leaf_hashes.len() == 1 {
        return Ok(leaf_hashes[0]);
    }

    let mut current_level = leaf_hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        for chunk in current_level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };

            // Hash the pair
            let mut hasher = Sha256::new();
            hasher.update(&left);
            hasher.update(&right);
            let parent_hash: [u8; 32] = hasher.finalize().into();

            next_level.push(parent_hash);
        }

        current_level = next_level;
    }

    Ok(current_level[0])
}

/// Calculates total fees for a share's job based on transaction data
fn calculate_share_fees(share: &Share) -> VerificationResult<u64> {
    // TODO: Rewrite this
    // This is a mock implementation only
    let base_fees = (share.job_id % 10000) * 100; // Simulate fee variation

    let time_bonus = (share.ntime % 1000) / 10;

    let total_fees = base_fees + time_bonus as u64;

    let clamped_fees = total_fees.clamp(100_000, 10_000_000);

    Ok(clamped_fees)
}

/// Calculates difficulty of a share based on its proof-of-work
fn calculate_share_difficulty(share: &Share) -> VerificationResult<u64> {
    let share_hash = calculate_share_pow_hash(share)?;
    pub const MIN_DIFFICULTY: u64 = 1;
    pub const MAX_DIFFICULTY: u64 = u64::MAX; // Practical limit for u64
    pub const BITCOIN_MAX_TARGET: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];
    let hash_u256 = primitive_types::U256::from_big_endian(&share_hash);

    let max_target = primitive_types::U256::from_big_endian(&BITCOIN_MAX_TARGET);

    if hash_u256.is_zero() {
        return Ok(u64::MAX);
    }

    let difficulty_u256 = max_target / hash_u256;

    let difficulty = difficulty_u256
        .as_u64()
        .clamp(MIN_DIFFICULTY, MAX_DIFFICULTY);

    Ok(difficulty)
}

/// Calculates the proof-of-work hash for a share
fn calculate_share_pow_hash(share: &Share) -> VerificationResult<[u8; 32]> {
    let mut hasher = Sha256::new();

    hasher.update(&share.version.to_le_bytes());
    hasher.update(&[0u8; 32]);
    hasher.update(&calculate_share_hash(share)?);
    hasher.update(&share.ntime.to_le_bytes());
    hasher.update(&[0xFF, 0xFF, 0x00, 0x1D]);
    hasher.update(&share.nonce.to_le_bytes());

    let first_hash = hasher.finalize();
    let mut second_hasher = Sha256::new();
    second_hasher.update(&first_hash);

    Ok(second_hasher.finalize().into())
}

/// Advanced merkle path verification with position tracking
pub fn verify_merkle_path_advanced(
    share: &Share,
    slice: &Slice,
    all_share_indices: &[u32],
) -> VerificationResult<bool> {
    if share.share_index >= slice.number_of_shares {
        return Err(VerificationError::ShareIndexOutOfBounds);
    }

    let basic_verification = verify_merkle_path(share, slice)?;
    if !basic_verification {
        return Ok(false);
    }

    let index_count = all_share_indices
        .iter()
        .filter(|&&idx| idx == share.share_index)
        .count();

    if index_count != 1 {
        return Ok(false);
    }

    Ok(true)
}

/// Validates that a collection of shares forms a valid merkle tree
pub fn validate_shares_merkle_consistency(
    shares: &[Share],
    expected_root: &U256,
) -> VerificationResult<bool> {
    if shares.is_empty() {
        return Ok(false);
    }

    let mut sorted_shares = shares.to_vec();
    sorted_shares.sort_by_key(|s| s.share_index);

    for (i, share) in sorted_shares.iter().enumerate() {
        if share.share_index != i as u32 {
            return Ok(false); // Non-sequential indices
        }
    }

    let share_hashes: Result<Vec<[u8; 32]>, _> =
        sorted_shares.iter().map(calculate_share_hash).collect();

    let hashes = share_hashes?;
    let calculated_root = build_merkle_tree(&hashes)?;

    let expected_root_bytes: [u8; 32] = (*expected_root)
        .inner_as_ref()
        .try_into()
        .map_err(|_| VerificationError::InvalidMerklePath)?;

    Ok(calculated_root == expected_root_bytes)
}
