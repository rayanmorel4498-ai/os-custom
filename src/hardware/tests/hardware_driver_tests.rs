extern crate alloc;

use redmi_hardware::*;
use std::sync::Arc;

#[test]
fn hardware_driver_service_exists() {
    // Vérifier que le type existe et compile
    let _service_type = std::any::type_name::<HardwareDriverService>();
    assert!(!_service_type.is_empty());
}

#[test]
fn secure_mmio_mapping_exists() {
    // Vérifier que le type de sécurité existe
    let _mapping_type = std::any::type_name::<SecureMmioMapping>();
    assert!(!_mapping_type.is_empty());
}

#[test]
fn hardware_command_pool_types_exist() {
    // Vérifier les types de la pool
    let _cmd_type = std::any::type_name::<CommandType>();
    let _req_type = std::any::type_name::<HardwareRequest>();
    let _resp_type = std::any::type_name::<HardwareResponse>();
    assert!(!_cmd_type.is_empty());
    assert!(!_req_type.is_empty());
    assert!(!_resp_type.is_empty());
}

#[test]
fn command_types_all_present() {
    // Vérifier que tous les command types existent
    let _get_cpu = CommandType::GetCpuStatus;
    let _get_gpu = CommandType::GetGpuStatus;
    let _get_ram = CommandType::GetRamStatus;
    let _get_thermal = CommandType::GetThermalStatus;
    let _get_power = CommandType::GetPowerStatus;
    let _set_cpu = CommandType::SetCpuFreq;
    let _set_gpu = CommandType::SetGpuFreq;
    let _set_thermal = CommandType::SetThermalThrottle;
    let _set_brightness = CommandType::SetDisplayBrightness;
    let _recover = CommandType::RecoverComponent;
    let _health_poll = CommandType::HardwareHealthPoll;
}

#[test]
fn secure_mmio_mapping_initialization() {
    // Tester l'initialisation du mapping sécurisé
    let mapping = SecureMmioMapping::new();
    
    // Vérifier que les slots existent mais sont vides au départ
    for i in 0..16 {
        assert!(!mapping.is_valid_index(i), "Index {} should be empty initially", i);
    }
}

#[test]
fn secure_mmio_address_lookup() {
    let mapping = SecureMmioMapping::new();
    
    // L'adresse 0 n'existe pas (slot vide)
    assert!(mapping.get_address(0).is_none());
    
    // Index invalide
    assert!(mapping.get_address(999).is_none());
}

#[test]
fn hardware_pool_creation() {
    // Tester création d'une hardware pool
    let pool = Arc::new(HardwareCommandPool::new(100, 100));
    
    // Vérifier qu'on peut créer un driver avec la pool
    let _driver = HardwareDriver::new(pool.clone());
    
    // Vérifier les stats initiales (pool vide)
    assert_eq!(pool.pending_request_count(), 0);
    assert_eq!(pool.pending_response_count(), 0);
}

#[test]
fn hardware_request_structure() {
    let req = HardwareRequest {
        request_id: 1,
        command: CommandType::GetCpuStatus,
        parameters: vec![],
        timeout_ms: 1000,
        retry_count: 1,
        timestamp_ms: 0,
    };
    
    assert_eq!(req.request_id, 1);
    assert_eq!(req.command, CommandType::GetCpuStatus);
    assert_eq!(req.timeout_ms, 1000);
}

#[test]
fn hardware_response_structure() {
    let resp = HardwareResponse {
        request_id: 1,
        success: true,
        data: 2400,
        error_msg: None,
    };
    
    assert_eq!(resp.request_id, 1);
    assert!(resp.success);
    assert_eq!(resp.data, 2400);
}

#[test]
fn pool_enqueue_dequeue_requests() {
    let pool = HardwareCommandPool::new(10, 10);
    
    // Enqueue une requête
    let req_id = pool.enqueue_request(
        CommandType::GetCpuStatus,
        vec![],
        1000
    ).expect("Failed to enqueue");
    
    assert_eq!(req_id, 1);
    
    // Vérifier le comptage
    let (pending, _, total, _, _) = pool.get_stats();
    assert_eq!(pending, 1);
    assert_eq!(total, 1);
    
    // Dequeue
    let req = pool.dequeue_request().expect("Failed to dequeue");
    assert_eq!(req.request_id, 1);
    assert_eq!(req.command, CommandType::GetCpuStatus);
    
    // Queue devrait être vide maintenant
    let (pending, _, _, _, _) = pool.get_stats();
    assert_eq!(pending, 0);
}

#[test]
fn pool_response_queue() {
    let pool = HardwareCommandPool::new(10, 10);
    
    let resp = HardwareResponse {
        request_id: 1,
        success: true,
        data: 2400,
        error_msg: None,
    };
    
    // Enqueue une réponse
    pool.enqueue_response(resp).expect("Failed to enqueue response");
    
    // Vérifier
    let (_, pending, _, total, _) = pool.get_stats();
    assert_eq!(pending, 1);
    assert_eq!(total, 1);
    
    // Dequeue
    let resp = pool.dequeue_response().expect("Failed to dequeue response");
    assert_eq!(resp.request_id, 1);
    assert!(resp.success);
    assert_eq!(resp.data, 2400);
}

#[test]
fn pool_queue_full_errors() {
    let pool = HardwareCommandPool::new(2, 2);
    
    // Remplir la queue
    pool.enqueue_request(CommandType::GetCpuStatus, vec![], 1000).expect("First enqueue");
    pool.enqueue_request(CommandType::GetGpuStatus, vec![], 1000).expect("Second enqueue");
    
    // La queue est pleine maintenant
    let result = pool.enqueue_request(CommandType::GetRamStatus, vec![], 1000);
    assert!(result.is_err(), "Queue should be full");
    
    // Vérifier que les erreurs sont comptabilisées
    let (_, _, _, _, errors) = pool.get_stats();
    assert_eq!(errors, 1);
}

#[test]
fn pool_flush_requests() {
    let pool = HardwareCommandPool::new(10, 10);
    
    pool.enqueue_request(CommandType::GetCpuStatus, vec![], 1000).expect("Enqueue 1");
    pool.enqueue_request(CommandType::GetGpuStatus, vec![], 1000).expect("Enqueue 2");
    
    let pending_before = pool.pending_request_count();
    assert_eq!(pending_before, 2);
    
    let flushed = pool.flush_requests();
    assert_eq!(flushed, 2);
    
    let pending_after = pool.pending_request_count();
    assert_eq!(pending_after, 0);
}

#[test]
fn pool_flush_responses() {
    let pool = HardwareCommandPool::new(10, 10);
    
    pool.enqueue_response(HardwareResponse {
        request_id: 1,
        success: true,
        data: 0,
        error_msg: None,
    }).expect("Enqueue 1");
    
    pool.enqueue_response(HardwareResponse {
        request_id: 2,
        success: false,
        data: 0,
        error_msg: Some("test".into()),
    }).expect("Enqueue 2");
    
    let pending_before = pool.pending_response_count();
    assert_eq!(pending_before, 2);
    
    let flushed = pool.flush_responses();
    assert_eq!(flushed, 2);
    
    let pending_after = pool.pending_response_count();
    assert_eq!(pending_after, 0);
}

#[test]
fn command_type_distinctness() {
    // Vérifier que les types de commandes sont distincts
    assert_ne!(CommandType::GetCpuStatus, CommandType::GetGpuStatus);
    assert_ne!(CommandType::SetCpuFreq, CommandType::SetGpuFreq);
    assert_ne!(CommandType::RecoverComponent, CommandType::HardwareHealthPoll);
}

#[test]
fn hardware_driver_pool_batch_processing() {
    let pool = Arc::new(HardwareCommandPool::new(100, 100));
    let _driver = HardwareDriver::new(pool.clone());
    
    // Enqueue quelques requêtes via pool
    pool.enqueue_request(CommandType::GetCpuStatus, vec![], 1000).expect("Enqueue 1");
    pool.enqueue_request(CommandType::GetGpuStatus, vec![], 1000).expect("Enqueue 2");
    
    // Vérifier que les commandes sont en queue
    let pending = pool.pending_request_count();
    assert_eq!(pending, 2);
}
