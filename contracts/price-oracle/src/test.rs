#![cfg(test)]

use super::*;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events, Ledger},
    Address, Env,
};

fn setup() -> (Env, PriceOracleClient<'static>) {
    let env = Env::default();
    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);
    (env, client)
}

#[test]
fn test_init_admin_sets_admin_once() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);
    let admin = Address::generate(&env);

    client.init_admin(&admin);

    env.as_contract(&contract_id, || {
        assert!(crate::auth::_has_admin(&env));
        assert_eq!(crate::auth::_get_admin(&env), admin);
    });
}

#[test]
#[should_panic(expected = "Admin already initialised")]
fn test_init_admin_panics_when_called_twice() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);
    let first_admin = Address::generate(&env);
    let second_admin = Address::generate(&env);

    client.init_admin(&first_admin);
    client.init_admin(&second_admin);
}

#[test]
fn test_get_price_existing_asset() {
    let env = Env::default();
    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);
    env.ledger().set_timestamp(1_234_567_890);
    env.ledger().set_sequence_number(1);

    let asset = symbol_short!("NGN");
    client.set_price(&asset, &1_000_000_i128);

    let result = client.try_get_price(&asset);
    let retrieved_price = result.unwrap().unwrap();
    assert_eq!(retrieved_price.price, 1_000_000_i128);
    assert_eq!(retrieved_price.timestamp, 1_234_567_890);
    assert_eq!(retrieved_price.provider, contract_id);
}

#[test]
fn test_get_price_nonexistent_asset() {
    let env = Env::default();
    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);
    let asset = symbol_short!("BTC");

    let result = client.try_get_price(&asset);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().unwrap(), Error::AssetNotFound);
}

#[test]
fn test_get_price_multiple_assets() {
    let env = Env::default();
    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);
    let ngn = symbol_short!("NGN");
    let kes = symbol_short!("KES");

    client
        .try_set_price(&ngn, &1_000_000_i128)
        .unwrap()
        .unwrap();
    client
        .try_set_price(&kes, &50_000_000_000_i128)
        .unwrap()
        .unwrap();

    assert_eq!(
        client.try_get_price(&ngn).unwrap().unwrap().price,
        1_000_000_i128
    );
    assert_eq!(
        client.try_get_price(&kes).unwrap().unwrap().price,
        50_000_000_000_i128
    );
}

#[test]
fn test_get_price_after_update() {
    let env = Env::default();
    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);
    let asset = symbol_short!("NGN");

    env.ledger().set_timestamp(1_234_567_890);
    env.ledger().set_sequence_number(1);
    client
        .try_set_price(&asset, &1_000_000_i128)
        .unwrap()
        .unwrap();

    let initial = client.try_get_price(&asset).unwrap().unwrap();
    assert_eq!(initial.price, 1_000_000_i128);
    assert_eq!(initial.timestamp, 1_234_567_890);

    env.ledger().set_timestamp(1_234_567_900);
    env.ledger().set_sequence_number(2);
    client
        .try_set_price(&asset, &1_200_000_i128)
        .unwrap()
        .unwrap();

    let updated = client.try_get_price(&asset).unwrap().unwrap();
    assert_eq!(updated.price, 1_200_000_i128);
    assert_eq!(updated.timestamp, 1_234_567_900);
}

#[test]
fn test_get_price_safe_nonexistent_returns_none() {
    let (_, client) = setup();
    assert_eq!(client.get_price_safe(&symbol_short!("NGN")), None);
}

#[test]
fn test_get_all_assets_returns_tracked_symbols() {
    let (_, client) = setup();
    let ngn = symbol_short!("NGN");
    let kes = symbol_short!("KES");

    client.set_price(&ngn, &1_500_i128);
    client.set_price(&kes, &800_i128);

    let assets = client.get_all_assets();
    assert_eq!(assets.len(), 2);
    assert!(assets.contains(&ngn));
    assert!(assets.contains(&kes));
}

#[test]
fn test_set_price_uses_current_ledger_timestamp() {
    let env = Env::default();
    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);
    let asset = symbol_short!("NGN");

    env.ledger().set_timestamp(1_700_000_123);
    env.ledger().set_sequence_number(77);
    client.set_price(&asset, &950_i128);

    let stored = client.get_price(&asset);
    assert_eq!(stored.price, 950_i128);
    assert_eq!(stored.timestamp, 1_700_000_123);
}

#[test]
fn test_update_price_provider_can_store_new_price() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let provider = Address::generate(&env);
    let asset = symbol_short!("XLM");

    env.as_contract(&contract_id, || {
        crate::auth::_set_admin(&env, &admin);
        crate::auth::_add_provider(&env, &provider);
    });

    env.ledger().set_timestamp(1_700_000_500);
    env.ledger().set_sequence_number(2);
    client.update_price(&provider, &asset, &1_500_000_i128);

    let stored = client.get_price(&asset);
    assert_eq!(stored.price, 1_500_000_i128);
    assert_eq!(stored.timestamp, 1_700_000_500);
}

#[test]
#[should_panic(expected = "Unauthorised: caller is not a whitelisted provider")]
fn test_update_price_unauthorized_rejection() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let unauthorized_address = Address::generate(&env);

    env.as_contract(&contract_id, || {
        crate::auth::_set_admin(&env, &admin);
    });

    client.update_price(
        &unauthorized_address,
        &symbol_short!("NGN"),
        &50_000_000_000_i128,
    );
}

#[test]
fn test_update_price_rejects_unapproved_symbol() {
    let env = Env::default();
    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let provider = Address::generate(&env);

    env.as_contract(&contract_id, || {
        crate::auth::_set_admin(&env, &admin);
        crate::auth::_add_provider(&env, &provider);
    });

    let asset = symbol_short!("ETH");
    let price: i128 = 1_000_000;

    match client.try_update_price(&provider, &asset, &price) {
        Err(Ok(e)) => assert_eq!(e, Error::InvalidAssetSymbol),
        other => panic!("expected InvalidAssetSymbol, got {:?}", other),
    }
}

#[test]
fn test_update_price_multiple_updates() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let provider = Address::generate(&env);
    let asset = symbol_short!("NGN");

    env.as_contract(&contract_id, || {
        crate::auth::_set_admin(&env, &admin);
        crate::auth::_add_provider(&env, &provider);
    });

    client.update_price(&provider, &asset, &1_000_000_i128);
    client.update_price(&provider, &asset, &1_200_000_i128);

    let stored = client.get_price(&asset);
    assert_eq!(stored.price, 1_200_000_i128);
}

#[test]
fn test_update_price_emits_event() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register(PriceOracle, ());
    let client = PriceOracleClient::new(&env, &contract_id);

    let admin = Address::generate(&env);
    let provider = Address::generate(&env);
    let asset = symbol_short!("NGN");
    let price: i128 = 1_500_000;

    env.as_contract(&contract_id, || {
        crate::auth::_set_admin(&env, &admin);
        crate::auth::_add_provider(&env, &provider);
    });

    env.ledger().set_timestamp(1_700_000_000);
    client.update_price(&provider, &asset, &price);

    let events = env.events().all();
    assert!(!events.events().is_empty());
}

#[test]
fn test_calculate_percentage_change_bps_for_increase() {
    assert_eq!(
        calculate_percentage_change_bps(1_000_000, 1_200_000),
        Some(2_000)
    );
}

#[test]
fn test_calculate_percentage_change_bps_for_drop() {
    assert_eq!(
        calculate_percentage_change_bps(1_000_000, 800_000),
        Some(-2_000)
    );
}

#[test]
fn test_calculate_percentage_difference_bps_is_absolute() {
    assert_eq!(
        calculate_percentage_difference_bps(1_000_000, 800_000),
        Some(2_000)
    );
    assert_eq!(
        calculate_percentage_difference_bps(1_000_000, 1_250_000),
        Some(2_500)
    );
}

#[test]
fn test_calculate_percentage_change_returns_none_for_zero_baseline() {
    assert_eq!(calculate_percentage_change_bps(0, 1_000_000), None);
    assert_eq!(calculate_percentage_difference_bps(0, 1_000_000), None);
}

#[test]
fn test_is_timestamp_stale_returns_true_after_24_hours() {
    let (env, client) = setup();
    env.ledger().set_timestamp(1_700_086_401);
    env.ledger().set_sequence_number(1);

    assert!(client.is_timestamp_stale(&1_700_000_000));
}

#[test]
fn test_is_timestamp_stale_returns_false_at_24_hour_boundary() {
    let (env, client) = setup();
    env.ledger().set_timestamp(1_700_086_400);
    env.ledger().set_sequence_number(1);

    assert!(!client.is_timestamp_stale(&1_700_000_000));
}

#[test]
fn test_is_timestamp_stale_returns_false_for_future_timestamp() {
    let (env, client) = setup();
    env.ledger().set_timestamp(1_700_000_000);
    env.ledger().set_sequence_number(1);

    assert!(!client.is_timestamp_stale(&1_700_000_100));
}
