#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, symbol_short, Address, Env, Symbol,
};

use crate::types::PriceData;

const PRICE_DATA_KEY: Symbol = symbol_short!("prices");

/// Error types for the price oracle contract
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Asset does not exist in the price oracle.
    AssetNotFound = 1,
    /// Unauthorized caller - not a whitelisted provider.
    Unauthorized = 2,
    /// Asset symbol is not in the approved list (NGN, KES, GHS)
    InvalidAssetSymbol = 3,
    /// Stake withdrawal amount must be greater than zero.
    InvalidStakeAmount = 4,
    /// Validator already has a pending unbonding request.
    UnbondingAlreadyQueued = 5,
    /// Validator does not have an unbonding request.
    UnbondingRequestNotFound = 6,
    /// The minimum unbonding delay has not elapsed yet.
    UnbondingDelayActive = 7,
    /// The queued unbonding request was already released.
    UnbondingAlreadyReleased = 8,
    /// The current ledger plus the unbonding delay overflowed.
    LedgerSequenceOverflow = 9,
}

/// Event emitted when a price is updated
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PriceUpdated {
    pub source: Address,
    pub asset: Symbol,
    pub price: i128,
    pub timestamp: u64,
}

/// Event emitted when the admin address is changed
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChanged {
    pub previous_admin: Option<Address>,
    pub new_admin: Address,
}

#[contract]
pub struct PriceOracle;

/// Returns the signed percentage change in basis points.
///
/// Example: 1_000_000 -> 1_200_000 returns 2_000 (20.00%).
/// Example: 1_000_000 -> 800_000 returns -2_000 (-20.00%).
/// Returns `None` when `old_price` is zero because the percentage change is undefined.
pub fn calculate_percentage_change_bps(old_price: i128, new_price: i128) -> Option<i128> {
    if old_price == 0 {
        return None;
    }

    let delta = new_price.checked_sub(old_price)?;
    let scaled = delta.checked_mul(10_000)?;
    scaled.checked_div(old_price)
}

/// Returns the absolute percentage difference in basis points.
///
/// This is convenient for flash-crash or spike detection because the caller can
/// compare the result directly against a threshold without worrying about direction.
pub fn calculate_percentage_difference_bps(old_price: i128, new_price: i128) -> Option<i128> {
    calculate_percentage_change_bps(old_price, new_price).map(i128::abs)
}

#[contractimpl]
impl PriceOracle {
    /// Initialise the contract admin once.
    pub fn init_admin(env: Env, address: Address) {
        if crate::auth::_has_admin(&env) {
            panic!("Admin already initialised");
        }

        address.require_auth();
        crate::auth::_set_admin(&env, &address);
    }

    /// Get the price data for a specific asset.
    pub fn get_price(env: Env, asset: Symbol) -> Result<PriceData, Error> {
        let storage = env.storage().persistent();
        let prices: soroban_sdk::Map<Symbol, PriceData> = storage
            .get(&PRICE_DATA_KEY)
            .unwrap_or_else(|| soroban_sdk::Map::new(&env));

        match prices.get(asset) {
            Some(price_data) => Ok(price_data),
            None => Err(Error::AssetNotFound),
        }
    }

    /// Returns `None` instead of an error when the asset is not found.
    pub fn get_price_safe(env: Env, asset: Symbol) -> Option<PriceData> {
        let prices: soroban_sdk::Map<Symbol, PriceData> = env
            .storage()
            .persistent()
            .get(&PRICE_DATA_KEY)
            .unwrap_or_else(|| soroban_sdk::Map::new(&env));
        prices.get(asset)
    }

    /// Returns a vector of all currently tracked asset symbols.
    pub fn get_all_assets(env: Env) -> soroban_sdk::Vec<Symbol> {
        let prices: soroban_sdk::Map<Symbol, PriceData> = env
            .storage()
            .persistent()
            .get(&PRICE_DATA_KEY)
            .unwrap_or_else(|| soroban_sdk::Map::new(&env));
        prices.keys()
    }

    /// Return true when a price timestamp is older than 24 hours.
    pub fn is_timestamp_stale(env: Env, timestamp: u64) -> bool {
        let current_timestamp = env.ledger().timestamp();
        current_timestamp > timestamp && current_timestamp - timestamp > 86_400
    }

    /// Set the price data for a specific asset.
    pub fn set_price(env: Env, asset: Symbol, val: i128) -> Result<(), Error> {
        let storage = env.storage().persistent();
        let mut prices: soroban_sdk::Map<Symbol, PriceData> = storage
            .get(&PRICE_DATA_KEY)
            .unwrap_or_else(|| soroban_sdk::Map::new(&env));

        let price_data = PriceData {
            price: val,
            timestamp: env.ledger().timestamp(),
            provider: env.current_contract_address(),
        };

        prices.set(asset, price_data);
        storage.set(&PRICE_DATA_KEY, &prices);
        Ok(())
    }

    /// Update the price for a specific asset (authorized backend relayer function)
    ///
    /// # Arguments
    /// * `env` - The contract environment
    /// * `source` - The address of the authorized backend relayer
    /// * `asset` - The asset symbol to update
    /// * `price` - The new price (as i128)
    ///
    /// # Errors
    /// * `Error::InvalidAssetSymbol` - If `asset` is not NGN, KES, or GHS
    ///
    /// # Panics
    /// If `source` is not a whitelisted provider.
    pub fn update_price(
        env: Env,
        source: Address,
        asset: Symbol,
        price: i128,
    ) -> Result<(), Error> {
        if !asset_symbol::is_approved_asset_symbol(asset.clone()) {
            return Err(Error::InvalidAssetSymbol);
        }

        if !crate::auth::_is_provider(&env, &source) {
            panic!("Unauthorised: caller is not a whitelisted provider");
        }

        source.require_auth();

        let storage = env.storage().persistent();
        let mut prices: soroban_sdk::Map<Symbol, PriceData> = storage
            .get(&PRICE_DATA_KEY)
            .unwrap_or_else(|| soroban_sdk::Map::new(&env));

        let timestamp = env.ledger().timestamp();
        let price_data = PriceData {
            price,
            timestamp,
            provider: source.clone(),
        };

        prices.set(asset.clone(), price_data);
        storage.set(&PRICE_DATA_KEY, &prices);

        PriceUpdated {
            source,
            asset,
            price,
            timestamp,
        }
        .publish(&env);

        Ok(())
    }

    /// Queue a validator stake withdrawal behind the slashing delay.
    pub fn request_stake_unbonding(
        env: Env,
        validator: Address,
        amount: i128,
    ) -> Result<slashing::UnbondingRequest, Error> {
        slashing::request_unbonding(&env, &validator, amount)
    }

    /// Release a queued validator stake withdrawal after the delay expires.
    pub fn release_unbonded_stake(env: Env, validator: Address) -> Result<i128, Error> {
        slashing::release_unbonded_stake(&env, &validator)
    }

    /// Inspect a validator's queued unbonding request.
    pub fn get_unbonding_request(
        env: Env,
        validator: Address,
    ) -> Option<slashing::UnbondingRequest> {
        slashing::get_unbonding_request(&env, &validator)
    }

    /// Return the enforced unbonding delay in ledgers.
    pub fn min_unbonding_delay_ledgers() -> u32 {
        slashing::MIN_UNBONDING_DELAY_LEDGERS
    }
}

mod asset_symbol;
mod auth;
pub mod math;
mod median;
pub mod slashing;
mod test;
mod types;
