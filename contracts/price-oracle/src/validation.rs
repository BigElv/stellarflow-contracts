//! Liquidity volume validation module — flash loan manipulation prevention.
//!
//! Aggregating market prices from thinly backed liquidity channels can expose
//! downstream financial engines to flash loan price manipulations. This module
//! implements explicit liquidity volume validation checks that terminate
//! transaction paths early if a validator node's reported pool liquidity falls
//! below the configured minimum security threshold.
//!
//! # Security Model
//! 
//! Flash loan attacks exploit temporary price dislocations in low-liquidity pools.
//! By requiring minimum liquidity thresholds, we ensure that price submissions
//! come from markets with sufficient depth to resist manipulation.
//!
//! # Flow
//! 1. Admin sets liquidity threshold per asset via `set_liquidity_threshold`.
//! 2. Provider submits price + liquidity data via `update_price`.
//! 3. Contract validates liquidity meets threshold before accepting submission.
//! 4. Submissions below threshold are rejected with `LiquidityBelowThreshold` error.
//!
//! # Storage layout
//! | Key                                  | Type      | Description                                    |
//! |--------------------------------------|-----------|------------------------------------------------|
//! | `DataKey::LiquidityThreshold(Symbol)` | `i128`    | Minimum liquidity required per asset (stroops) |
//! | `DataKey::ProviderReportedLiquidity(Address, Symbol)` | `i128` | Last reported liquidity by provider for asset |
//! | `DataKey::LastLiquidityValidation(Symbol)` | `u64` | Timestamp of last successful validation |

use soroban_sdk::{Address, Env, Symbol};

use crate::types::DataKey;
use crate::ContractError;

/// Minimum allowed liquidity threshold (1 XLM equivalent = 10_000_000 stroops).
/// Prevents admins from setting unreasonably low thresholds that defeat the purpose.
pub const MIN_LIQUIDITY_THRESHOLD: i128 = 10_000_000;

/// Maximum reasonable liquidity threshold (1 billion XLM equivalent).
/// Prevents accidental misconfiguration that would reject all submissions.
pub const MAX_LIQUIDITY_THRESHOLD: i128 = 1_000_000_000_0000000;

/// Multiplier for low-liquidity slash penalty (basis points).
/// Applied when provider submits prices from pools below the threshold.
pub const LOW_LIQUIDITY_SLASH_MULTIPLIER: i128 = 5;

// ─────────────────────────────────────────────────────────────────────────────
// Storage Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read the minimum liquidity threshold for an asset.
/// Returns None if no threshold has been configured.
pub fn get_liquidity_threshold(env: &Env, asset: &Symbol) -> Option<i128> {
    env.storage()
        .persistent()
        .get(&DataKey::LiquidityThreshold(asset.clone()))
}

/// Set the minimum liquidity threshold for an asset.
/// Must be within MIN_LIQUIDITY_THRESHOLD..MAX_LIQUIDITY_THRESHOLD range.
fn set_liquidity_threshold(env: &Env, asset: &Symbol, threshold: i128) {
    env.storage()
        .persistent()
        .set(&DataKey::LiquidityThreshold(asset.clone()), &threshold);
}

/// Read the last reported liquidity from a specific provider for an asset.
/// Returns None if the provider has never reported liquidity for this asset.
pub fn get_provider_liquidity(env: &Env, provider: &Address, asset: &Symbol) -> Option<i128> {
    env.storage()
        .persistent()
        .get(&DataKey::ProviderReportedLiquidity(
            provider.clone(),
            asset.clone(),
        ))
}

/// Store the liquidity value reported by a provider for an asset.
fn set_provider_liquidity(env: &Env, provider: &Address, asset: &Symbol, liquidity: i128) {
    env.storage().persistent().set(
        &DataKey::ProviderReportedLiquidity(provider.clone(), asset.clone()),
        &liquidity,
    );
}

/// Record the timestamp of the last successful liquidity validation for an asset.
fn set_last_validation_timestamp(env: &Env, asset: &Symbol) {
    let timestamp = env.ledger().timestamp();
    env.storage()
        .persistent()
        .set(&DataKey::LastLiquidityValidation(asset.clone()), &timestamp);
}

/// Read the timestamp of the last successful liquidity validation for an asset.
pub fn get_last_validation_timestamp(env: &Env, asset: &Symbol) -> Option<u64> {
    env.storage()
        .persistent()
        .get(&DataKey::LastLiquidityValidation(asset.clone()))
}

// ─────────────────────────────────────────────────────────────────────────────
// Core Validation Logic
// ─────────────────────────────────────────────────────────────────────────────

/// Validate that reported pool liquidity meets the configured minimum threshold.
///
/// This function is called during `update_price` to ensure price submissions
/// come from sufficiently liquid markets that cannot be easily manipulated via
/// flash loans or other short-term capital injection attacks.
///
/// # Parameters
/// - `env`: Soroban environment
/// - `asset`: The asset pair being priced (e.g. "XLM/USD")
/// - `provider`: Address of the relayer submitting the price
/// - `reported_liquidity`: Total pool liquidity value reported by the provider (in stroops)
///
/// # Returns
/// - `Ok(())` if liquidity meets or exceeds the threshold, or no threshold is set
/// - `Err(ContractError::LiquidityBelowThreshold)` if liquidity is insufficient
/// - `Err(ContractError::InvalidLiquidity)` if reported liquidity is negative or zero
///
/// # Security Properties
/// 1. **Early termination**: Transaction is rejected before price enters buffer
/// 2. **Per-asset thresholds**: Different assets can have different liquidity requirements
/// 3. **Provider tracking**: Historical liquidity data enables reputation scoring
/// 4. **Audit trail**: Timestamps allow reconstruction of liquidity history
///
/// # Example
/// ```rust
/// // Admin sets 100M stroops minimum liquidity for XLM/USD
/// set_liquidity_threshold_internal(&env, &Symbol::new(&env, "XLM_USD"), 100_000_000);
///
/// // Provider attempts to submit price with 50M liquidity
/// let result = validate_liquidity(
///     &env,
///     &Symbol::new(&env, "XLM_USD"),
///     &provider_addr,
///     50_000_000
/// );
/// // Result: Err(ContractError::LiquidityBelowThreshold)
/// ```
pub fn validate_liquidity(
    env: &Env,
    asset: &Symbol,
    provider: &Address,
    reported_liquidity: i128,
) -> Result<(), ContractError> {
    // Reject negative or zero liquidity values
    if reported_liquidity <= 0 {
        return Err(ContractError::InvalidLiquidity);
    }

    // Check if a liquidity threshold has been configured for this asset
    let threshold = match get_liquidity_threshold(env, asset) {
        Some(t) => t,
        None => {
            // No threshold configured — validation passes by default.
            // This allows gradual rollout: assets without explicit thresholds
            // continue to accept all submissions until governance configures them.
            return Ok(());
        }
    };

    // Compare reported liquidity against the configured threshold
    if reported_liquidity < threshold {
        // Emit event for monitoring and alerting
        env.events().publish(
            (Symbol::new(env, "liquidity_violation"),),
            (
                asset.clone(),
                provider.clone(),
                reported_liquidity,
                threshold,
            ),
        );

        // Store the insufficient liquidity value for reputation tracking
        set_provider_liquidity(env, provider, asset, reported_liquidity);

        return Err(ContractError::LiquidityBelowThreshold);
    }

    // Validation passed — record the successful submission
    set_provider_liquidity(env, provider, asset, reported_liquidity);
    set_last_validation_timestamp(env, asset);

    // Emit success event for monitoring
    env.events().publish(
        (Symbol::new(env, "liquidity_validated"),),
        (
            asset.clone(),
            provider.clone(),
            reported_liquidity,
            threshold,
        ),
    );

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Admin Configuration Functions
// ─────────────────────────────────────────────────────────────────────────────

/// Internal helper to set liquidity threshold with validation.
///
/// Enforces MIN_LIQUIDITY_THRESHOLD and MAX_LIQUIDITY_THRESHOLD bounds to
/// prevent misconfiguration. Called by the public `set_liquidity_threshold`
/// function after authorization checks.
///
/// # Parameters
/// - `env`: Soroban environment
/// - `asset`: Asset pair to configure
/// - `threshold`: Minimum liquidity value in stroops
///
/// # Returns
/// - `Ok(())` if threshold is valid and stored
/// - `Err(ContractError::InvalidLiquidityThreshold)` if out of bounds
pub fn set_liquidity_threshold_internal(
    env: &Env,
    asset: &Symbol,
    threshold: i128,
) -> Result<(), ContractError> {
    // Validate threshold is within acceptable range
    if threshold < MIN_LIQUIDITY_THRESHOLD {
        return Err(ContractError::InvalidLiquidityThreshold);
    }

    if threshold > MAX_LIQUIDITY_THRESHOLD {
        return Err(ContractError::InvalidLiquidityThreshold);
    }

    // Store the threshold
    set_liquidity_threshold(env, asset, threshold);

    // Emit configuration event
    env.events().publish(
        (Symbol::new(env, "liquidity_threshold_set"),),
        (asset.clone(), threshold),
    );

    Ok(())
}

/// Remove the liquidity threshold for an asset.
///
/// After removal, price submissions for this asset will no longer undergo
/// liquidity validation. Use with caution — removing thresholds re-exposes
/// the contract to flash loan manipulation risks.
///
/// # Parameters
/// - `env`: Soroban environment
/// - `asset`: Asset pair to remove threshold from
pub fn remove_liquidity_threshold_internal(env: &Env, asset: &Symbol) {
    env.storage()
        .persistent()
        .remove(&DataKey::LiquidityThreshold(asset.clone()));

    env.events().publish(
        (Symbol::new(env, "liquidity_threshold_removed"),),
        asset.clone(),
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Liquidity-Based Slashing Integration
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate additional slash penalty for low-liquidity submissions.
///
/// Providers who repeatedly submit prices from thin markets receive graduated
/// penalties. This function returns a multiplier to be applied on top of the
/// standard deviation-based slashing.
///
/// # Penalty tiers (based on liquidity as % of threshold)
/// - **≥ 100%**: No penalty (1× multiplier)
/// - **75-99%**: Minor penalty (2× multiplier)
/// - **50-74%**: Moderate penalty (4× multiplier)
/// - **25-49%**: Significant penalty (8× multiplier)
/// - **< 25%**: Severe penalty (16× multiplier)
///
/// # Parameters
/// - `reported_liquidity`: The liquidity value the provider submitted
/// - `threshold`: The configured minimum threshold for this asset
///
/// # Returns
/// Multiplier to apply to base slash amount (1-16×)
pub fn calculate_liquidity_slash_multiplier(reported_liquidity: i128, threshold: i128) -> i128 {
    if threshold == 0 {
        return 1;
    }

    // Calculate liquidity as percentage of threshold (in basis points for precision)
    let percentage = (reported_liquidity * 10_000) / threshold;

    if percentage >= 10_000 {
        // >= 100% of threshold — no penalty
        1
    } else if percentage >= 7_500 {
        // 75-99% of threshold — minor penalty
        2
    } else if percentage >= 5_000 {
        // 50-74% of threshold — moderate penalty
        4
    } else if percentage >= 2_500 {
        // 25-49% of threshold — significant penalty
        8
    } else {
        // < 25% of threshold — severe penalty
        16
    }
}

/// Report a liquidity violation and apply graduated slashing.
///
/// Called by monitoring systems or governance when a provider is detected
/// submitting prices from pools below the configured liquidity threshold.
/// Integrates with the existing slashing engine to deduct stake.
///
/// # Parameters
/// - `env`: Soroban environment
/// - `executor`: Admin executing the slash
/// - `provider`: The relayer being penalized
/// - `asset`: Asset pair the violation occurred on
/// - `reported_liquidity`: The insufficient liquidity value submitted
/// - `base_slash_amount`: Base penalty before liquidity multiplier
///
/// # Returns
/// - `Ok(())` if slash executed successfully
/// - `Err(...)` if slashing fails (insufficient stake, etc.)
pub fn slash_for_low_liquidity(
    env: &Env,
    executor: &Address,
    provider: &Address,
    asset: &Symbol,
    reported_liquidity: i128,
    base_slash_amount: i128,
) -> Result<(), ContractError> {
    // Get the configured threshold
    let threshold = get_liquidity_threshold(env, asset)
        .ok_or(ContractError::InvalidLiquidityThreshold)?;

    // Calculate the liquidity-based multiplier
    let liquidity_mult = calculate_liquidity_slash_multiplier(reported_liquidity, threshold);

    // Scale the base slash amount
    let scaled_amount = base_slash_amount
        .checked_mul(liquidity_mult)
        .ok_or(ContractError::InvalidSlashAmount)?;

    // Execute the slash via the existing slashing engine
    crate::slashing::execute_slash_internal(env, executor, provider, scaled_amount)
        .map_err(|_| ContractError::InsufficientStake)?;

    // Emit liquidity-specific slash event
    env.events().publish(
        (Symbol::new(env, "liquidity_slash_executed"),),
        (
            provider.clone(),
            asset.clone(),
            reported_liquidity,
            threshold,
            liquidity_mult,
            scaled_amount,
        ),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_liquidity_slash_multiplier() {
        // Test at 100% threshold — no penalty
        assert_eq!(calculate_liquidity_slash_multiplier(100, 100), 1);

        // Test at 80% threshold — minor penalty
        assert_eq!(calculate_liquidity_slash_multiplier(80, 100), 2);

        // Test at 60% threshold — moderate penalty
        assert_eq!(calculate_liquidity_slash_multiplier(60, 100), 4);

        // Test at 40% threshold — significant penalty
        assert_eq!(calculate_liquidity_slash_multiplier(40, 100), 8);

        // Test at 20% threshold — severe penalty
        assert_eq!(calculate_liquidity_slash_multiplier(20, 100), 16);

        // Test at exact boundaries
        assert_eq!(calculate_liquidity_slash_multiplier(75, 100), 2); // 75% = 2×
        assert_eq!(calculate_liquidity_slash_multiplier(50, 100), 4); // 50% = 4×
        assert_eq!(calculate_liquidity_slash_multiplier(25, 100), 8); // 25% = 8×
    }

    #[test]
    fn test_zero_threshold_handling() {
        // Zero threshold should not cause division by zero
        assert_eq!(calculate_liquidity_slash_multiplier(100, 0), 1);
    }
}
