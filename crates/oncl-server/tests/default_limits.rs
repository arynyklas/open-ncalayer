use oncl_pki::resource::ResourceLimits;
use oncl_server::config::ServerConfig;

#[test]
fn the_default_profile_guarantees_one_gibibyte_documents_inside_the_engine_ceiling() {
    let config = ServerConfig::default();
    let engine = ResourceLimits::default();
    assert_eq!(config.input_bytes, 1_073_741_824);
    assert_eq!(config.temp_per_operation, 8_589_934_592);
    assert_eq!(config.total_temp, 17_179_869_184);
    assert_eq!(config.input_bytes, engine.input_bytes);
    assert!(config.total_temp >= config.temp_per_operation);
    config.validate().unwrap();
}

#[test]
fn an_operator_may_raise_the_input_limit_above_the_default() {
    let config = ServerConfig {
        input_bytes: 4 * 1_073_741_824,
        ..ServerConfig::default()
    };
    config.validate().unwrap();
}

#[test]
fn the_container_allowance_defaults_to_the_engine_and_reaches_it() {
    let config = ServerConfig::default();
    assert_eq!(
        config.container_bytes,
        ResourceLimits::default().container_bytes
    );
    let tight = ServerConfig {
        input_bytes: 3,
        container_bytes: 5,
        ..ServerConfig::default()
    };
    tight.validate().unwrap();
    assert_eq!(tight.limits().input_bytes, 3);
    assert_eq!(tight.limits().container_bytes, 5);
    assert_eq!(tight.aggregate_limits().container_bytes, 5);
}

#[test]
fn a_nonsensical_container_allowance_is_refused() {
    for container_bytes in [0, u64::MAX, u64::MAX - 1_073_741_824] {
        let config = ServerConfig {
            container_bytes,
            ..ServerConfig::default()
        };
        assert!(config.validate().is_err(), "{container_bytes}");
    }
    // The largest sum that still fits u64 (input + container + framing + 64 KiB) is accepted.
    let defaults = ServerConfig::default();
    let config = ServerConfig {
        container_bytes: u64::MAX - defaults.input_bytes - defaults.framing_bytes - 65_536,
        ..defaults
    };
    config.validate().unwrap();
}
