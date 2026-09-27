use pqc_hw::runtime::{Health, Runtime};

#[test]
fn hardware_failure_falls_back_once_and_degrades() {
    let mut runtime = Runtime::new(false);
    let mut hardware_calls = 0;
    let value = runtime
        .execute(
            || {
                hardware_calls += 1;
                Err::<u8, _>("dma fault")
            },
            || Ok(42),
        )
        .unwrap();
    assert_eq!(value, 42);
    assert_eq!(hardware_calls, 1);
    assert_eq!(runtime.health(), Health::Degraded);
    assert_eq!(runtime.failure_count(), 1);

    let value = runtime
        .execute(|| panic!("degraded hardware called"), || Ok::<_, &str>(43))
        .unwrap();
    assert_eq!(value, 43);
}

#[test]
fn successful_self_test_restores_degraded_runtime() {
    let mut runtime = Runtime::new(false);
    let _: u8 = runtime
        .execute(|| Err::<u8, _>("timeout"), || Ok(1))
        .unwrap();
    runtime.self_test(|| Ok::<_, &str>(())).unwrap();
    assert_eq!(runtime.health(), Health::Ready);
}

#[test]
fn operator_disable_is_sticky() {
    let mut runtime = Runtime::new(true);
    runtime.self_test(|| Ok::<_, &str>(())).unwrap();
    assert_eq!(runtime.health(), Health::Disabled);
    let value = runtime
        .execute(|| panic!("disabled hardware called"), || Ok::<_, &str>(7))
        .unwrap();
    assert_eq!(value, 7);
}
