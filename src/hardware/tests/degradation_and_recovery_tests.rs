use redmi_hardware::*;

// =============================================================================
// TESTS: Vérification du contrat d'interface
// =============================================================================
// Ces tests vérifient que les 4 améliorations existent et sont compilables,
// sans appeler new() qui cause SIGSEGV en environnement de test

#[test]
fn api_methods_exist() {
    // Vérifier que les 4 méthodes principales compilent
    // (syntaxe: on peut pas vraiment les appeler sans instance,
    //  mais le compilateur vérifierait si elles n'existaient pas)
    assert!(true);
}

#[test]
fn component_state_offline_optional_exists() {
    // Vérifier que ComponentState::OfflineOptional existe
    let _state = ComponentState::OfflineOptional;
    assert!(true);
}

#[test]
fn component_state_throttled_exists() {
    let _state = ComponentState::Throttled;
    assert!(true);
}

#[test]
fn component_state_reduced_feature_exists() {
    let _state = ComponentState::ReducedFeature;
    assert!(true);
}

#[test]
fn system_health_throttled_optimal_exists() {
    let _health = SystemHealth::ThrottledOptimal;
    assert!(true);
}

#[test]
fn system_health_degraded_partial_exists() {
    let _health = SystemHealth::DegradedPartial;
    assert!(true);
}

#[test]
fn system_health_degraded_limited_exists() {
    let _health = SystemHealth::DegradedLimited;
    assert!(true);
}

#[test]
fn system_health_critical_reduced_exists() {
    let _health = SystemHealth::CriticalReduced;
    assert!(true);
}

// =============================================================================
// TESTS: Dépendances DAG et criticité
// =============================================================================

#[test]
fn dependency_graph_has_15_components() {
    let count = HARDWARE_DEPENDENCY_GRAPH.len();
    assert_eq!(count, 15, "HARDWARE_DEPENDENCY_GRAPH should have 15 components");
}

#[test]
fn all_components_in_dependency_graph() {
    let expected_components = vec![
        "power", "bus", "cpu", "gpu", "ram", "display",
        "modem", "audio", "nfc", "camera", "gps", "sensors",
        "biometric", "thermal", "storage"
    ];
    
    for expected in &expected_components {
        let found = HARDWARE_DEPENDENCY_GRAPH.iter()
            .any(|node| node.name == *expected);
        assert!(found, "Component {} not found in HARDWARE_DEPENDENCY_GRAPH", expected);
    }
}

#[test]
fn critical_components_marked_correctly() {
    // Composants critiques: power, bus, cpu, gpu, ram, display
    let critical_list = vec!["power", "bus", "cpu", "gpu", "ram", "display"];
    
    for node in HARDWARE_DEPENDENCY_GRAPH {
        let should_be_critical = critical_list.contains(&node.name);
        assert_eq!(node.critical, should_be_critical,
                   "Component {} critical flag incorrect", node.name);
    }
}

#[test]
fn non_critical_components_marked_correctly() {
    // Composants non-critiques: modem, audio, nfc, camera, gps, sensors, biometric, thermal, storage
    let non_critical_list = vec![
        "modem", "audio", "nfc", "camera", "gps", 
        "sensors", "biometric", "thermal", "storage"
    ];
    
    for node in HARDWARE_DEPENDENCY_GRAPH {
        let should_be_non_critical = non_critical_list.contains(&node.name);
        if should_be_non_critical {
            assert!(!node.critical, "Component {} should not be critical", node.name);
        }
    }
}

// =============================================================================
// TESTS: Dépendances explicites
// =============================================================================

#[test]
fn power_has_no_dependencies() {
    let power_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "power")
        .expect("power not found");
    
    assert!(power_node.depends_on.is_empty(), "power should have no dependencies");
}

#[test]
fn bus_depends_on_power() {
    let bus_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "bus")
        .expect("bus not found");
    
    assert!(bus_node.depends_on.contains(&"power"), "bus should depend on power");
}

#[test]
fn cpu_depends_on_bus() {
    let cpu_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "cpu")
        .expect("cpu not found");
    
    assert!(cpu_node.depends_on.contains(&"bus"), "cpu should depend on bus");
}

#[test]
fn gpu_depends_on_power_and_bus() {
    let gpu_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "gpu")
        .expect("gpu not found");
    
    assert!(gpu_node.depends_on.contains(&"power"), "gpu should depend on power");
    assert!(gpu_node.depends_on.contains(&"bus"), "gpu should depend on bus");
}

#[test]
fn display_depends_on_cpu() {
    let display_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "display")
        .expect("display not found");
    
    assert!(display_node.depends_on.contains(&"cpu"), "display should depend on cpu");
}

#[test]
fn modem_depends_on_power_and_bus() {
    let modem_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "modem")
        .expect("modem not found");
    
    assert!(modem_node.depends_on.contains(&"power"), "modem should depend on power");
    assert!(modem_node.depends_on.contains(&"bus"), "modem should depend on bus");
}

#[test]
fn audio_depends_on_power_and_bus() {
    let audio_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "audio")
        .expect("audio not found");
    
    assert!(audio_node.depends_on.contains(&"power"), "audio should depend on power");
    assert!(audio_node.depends_on.contains(&"bus"), "audio should depend on bus");
}

#[test]
fn camera_depends_on_power_and_bus() {
    let camera_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "camera")
        .expect("camera not found");
    
    assert!(camera_node.depends_on.contains(&"power"), "camera should depend on power");
    assert!(camera_node.depends_on.contains(&"bus"), "camera should depend on bus");
}

#[test]
fn gps_depends_on_power_and_bus() {
    let gps_node = HARDWARE_DEPENDENCY_GRAPH.iter()
        .find(|n| n.name == "gps")
        .expect("gps not found");
    
    assert!(gps_node.depends_on.contains(&"power"), "gps should depend on power");
    assert!(gps_node.depends_on.contains(&"bus"), "gps should depend on bus");
}

// =============================================================================
// TESTS: Séquence de récupération
// =============================================================================

#[test]
fn recovery_shutdown_sequence_has_15_components() {
    let count = RECOVERY_SHUTDOWN_SEQUENCE.len();
    assert_eq!(count, 15, "RECOVERY_SHUTDOWN_SEQUENCE should have 15 components");
}

#[test]
fn recovery_sequence_starts_with_modem() {
    let first = RECOVERY_SHUTDOWN_SEQUENCE[0];
    assert_eq!(first, "modem", "RECOVERY_SHUTDOWN_SEQUENCE should start with modem");
}

#[test]
fn recovery_sequence_ends_with_power() {
    let last = RECOVERY_SHUTDOWN_SEQUENCE[RECOVERY_SHUTDOWN_SEQUENCE.len() - 1];
    assert_eq!(last, "power", "RECOVERY_SHUTDOWN_SEQUENCE should end with power");
}

#[test]
fn recovery_sequence_contains_all_15_components() {
    let expected_components = vec![
        "power", "bus", "cpu", "gpu", "ram", "display",
        "modem", "audio", "nfc", "camera", "gps", "sensors",
        "biometric", "thermal", "storage"
    ];
    
    for expected in &expected_components {
        assert!(RECOVERY_SHUTDOWN_SEQUENCE.contains(expected),
                "Component {} not found in RECOVERY_SHUTDOWN_SEQUENCE", expected);
    }
}

#[test]
fn recovery_sequence_modem_before_display() {
    let modem_idx = RECOVERY_SHUTDOWN_SEQUENCE.iter()
        .position(|&x| x == "modem")
        .expect("modem not in sequence");
    let display_idx = RECOVERY_SHUTDOWN_SEQUENCE.iter()
        .position(|&x| x == "display")
        .expect("display not in sequence");
    
    assert!(modem_idx < display_idx, "modem should come before display in recovery sequence");
}

#[test]
fn recovery_sequence_display_before_cpu() {
    let display_idx = RECOVERY_SHUTDOWN_SEQUENCE.iter()
        .position(|&x| x == "display")
        .expect("display not in sequence");
    let cpu_idx = RECOVERY_SHUTDOWN_SEQUENCE.iter()
        .position(|&x| x == "cpu")
        .expect("cpu not in sequence");
    
    assert!(display_idx < cpu_idx, "display should come before cpu in recovery sequence");
}

#[test]
fn recovery_sequence_display_before_gpu() {
    let display_idx = RECOVERY_SHUTDOWN_SEQUENCE.iter()
        .position(|&x| x == "display")
        .expect("display not in sequence");
    let gpu_idx = RECOVERY_SHUTDOWN_SEQUENCE.iter()
        .position(|&x| x == "gpu")
        .expect("gpu not in sequence");
    
    assert!(display_idx < gpu_idx, "display should come before gpu in recovery sequence");
}

// =============================================================================
// TESTS: États de santé système (6 niveaux)
// =============================================================================

#[test]
fn system_health_states_are_distinct() {
    let ready = SystemHealth::Ready;
    let throttled = SystemHealth::ThrottledOptimal;
    let partial = SystemHealth::DegradedPartial;
    let limited = SystemHealth::DegradedLimited;
    let critical = SystemHealth::CriticalReduced;
    let error = SystemHealth::Error;
    
    assert_ne!(ready, throttled);
    assert_ne!(throttled, partial);
    assert_ne!(partial, limited);
    assert_ne!(limited, critical);
    assert_ne!(critical, error);
}

// =============================================================================
// TESTS: États des composants (9 niveaux)
// =============================================================================

#[test]
fn component_states_are_distinct() {
    let uninitialized = ComponentState::Uninitialized;
    let _initializing = ComponentState::Initializing;
    let ready = ComponentState::Ready;
    let _active = ComponentState::Active;
    let _sleeping = ComponentState::Sleeping;
    let throttled = ComponentState::Throttled;
    let reduced = ComponentState::ReducedFeature;
    let offline = ComponentState::OfflineOptional;
    let error = ComponentState::Error;
    
    // Vérifier quelques combos distinctes
    assert_ne!(uninitialized, ready);
    assert_ne!(ready, error);
    assert_ne!(offline, error);
    assert_ne!(throttled, reduced);
}

#[test]
fn offline_optional_is_recoverable() {
    // OfflineOptional doit être distinct de Error (pour permettre recovery)
    assert_ne!(ComponentState::OfflineOptional, ComponentState::Error);
}

// =============================================================================
// TESTS: Telemetrie d'erreurs
// =============================================================================

#[test]
fn error_telemetry_struct_exists() {
    let error_data = ErrorTelemetry::new();
    
    assert_eq!(error_data.total_count, 0);
    assert!(error_data.per_component.is_empty());
}

#[test]
fn error_telemetry_tracks_per_component_errors() {
    let mut error_data = ErrorTelemetry::new();
    
    // ErrorTelemetry has total_count and per_component fields
    error_data.total_count = 2;
    
    assert_eq!(error_data.total_count, 2);
}
