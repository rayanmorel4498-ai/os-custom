use redmi_hardware::*;

#[test]
fn dependency_graph_exists() {
    assert!(!HARDWARE_DEPENDENCY_GRAPH.is_empty());
    assert_eq!(HARDWARE_DEPENDENCY_GRAPH.len(), 15);
}

#[test]
fn power_has_no_dependencies() {
    let power = HardwareManager::get_dependencies("power");
    assert!(power.is_some());
    let node = power.unwrap();
    assert_eq!(node.depends_on.len(), 0);
    assert!(node.critical);
}

#[test]
fn bus_depends_on_power() {
    let bus = HardwareManager::get_dependencies("bus");
    assert!(bus.is_some());
    let node = bus.unwrap();
    assert_eq!(node.depends_on, ["power"]);
    assert!(node.critical);
}

#[test]
fn cpu_depends_on_power_and_bus() {
    let cpu = HardwareManager::get_dependencies("cpu");
    assert!(cpu.is_some());
    let node = cpu.unwrap();
    assert!(node.depends_on.contains(&"power"));
    assert!(node.depends_on.contains(&"bus"));
    assert!(node.critical);
}

#[test]
fn non_critical_dependencies() {
    for comp in &["modem", "audio", "camera", "gps"] {
        let node = HardwareManager::get_dependencies(comp);
        assert!(node.is_some());
        assert!(!node.unwrap().critical);
    }
}

#[test]
fn recovery_sequence_is_reverse_order() {
    // Verifier que power est en dernier
    assert_eq!(RECOVERY_SHUTDOWN_SEQUENCE[RECOVERY_SHUTDOWN_SEQUENCE.len() - 1], "power");
    
    // Modem (tier 3) avant CPU (tier 2)
    let modem_pos = RECOVERY_SHUTDOWN_SEQUENCE.iter().position(|&x| x == "modem").unwrap();
    let cpu_pos = RECOVERY_SHUTDOWN_SEQUENCE.iter().position(|&x| x == "cpu").unwrap();
    assert!(modem_pos < cpu_pos);
}

#[test]
fn component_state_variants_exist() {
    // Juste vérifier que les nouveaux états compilent
    let _states = [
        ComponentState::Uninitialized,
        ComponentState::Initializing,
        ComponentState::Ready,
        ComponentState::Active,
        ComponentState::Sleeping,
        ComponentState::Throttled,
        ComponentState::ReducedFeature,
        ComponentState::OfflineOptional,
        ComponentState::Error,
    ];
    assert_eq!(_states.len(), 9);
}

#[test]
fn system_health_variants_exist() {
    let _health = [
        SystemHealth::Ready,
        SystemHealth::ThrottledOptimal,
        SystemHealth::DegradedPartial,
        SystemHealth::DegradedLimited,
        SystemHealth::CriticalReduced,
        SystemHealth::Error,
    ];
    assert_eq!(_health.len(), 6);
}

#[test]
fn dependency_node_structure() {
    // Vérifier qu'un nœud arbitraire a la bonne structure
    let display = HardwareManager::get_dependencies("display");
    assert!(display.is_some());
    let node = display.unwrap();
    
    assert_eq!(node.name, "display");
    assert!(!node.depends_on.is_empty());
    assert!(node.critical);
}

#[test]
fn recovery_sequence_completeness() {
    // Vérifier que tous les 15 composants sont dans la séquence d'arrêt
    let component_names = ["power", "bus", "cpu", "gpu", "ram", "display", "modem", "audio", "nfc", "camera", "gps", "sensors", "biometric", "thermal", "storage"];
    
    for comp in &component_names {
        assert!(RECOVERY_SHUTDOWN_SEQUENCE.contains(comp), "Missing {} in recovery sequence", comp);
    }
}
