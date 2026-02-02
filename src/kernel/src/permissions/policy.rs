
#[derive(Copy, Clone)]
pub struct AccessCaps {
    pub memory_limit: usize,
    pub cpu_quota: u8,
    pub allow_network: bool,
    pub allow_storage: bool,
    pub allow_sensors: bool,
    pub allow_camera: bool,
    pub allow_microphone: bool,
}

#[derive(Copy, Clone)]
pub enum AccessDevice {
    Network,
    Storage,
    Sensors,
    Camera,
    Microphone,
}

pub struct Policy;

impl Policy {
    pub fn memory_limit(component: PolicyComponent) -> usize {
        match component {
            PolicyComponent::Ia => 512 * 1024 * 1024,
            PolicyComponent::Audio => 128 * 1024 * 1024,
            PolicyComponent::Nfc => 32 * 1024 * 1024,
            PolicyComponent::Camera => 256 * 1024 * 1024,
            PolicyComponent::Gps => 16 * 1024 * 1024,
        }
    }

    pub fn cpu_quota(component: PolicyComponent) -> u8 {
        match component {
            PolicyComponent::Ia => 70,
            PolicyComponent::Audio => 40,
            PolicyComponent::Nfc => 10,
            PolicyComponent::Camera => 50,
            PolicyComponent::Gps => 5,
        }
    }

    pub fn allowed_devices(component: PolicyComponent) -> AccessCaps {
        match component {
            PolicyComponent::Ia => AccessCaps {
                memory_limit: Self::memory_limit(component),
                cpu_quota: Self::cpu_quota(component),
                allow_network: true,
                allow_storage: true,
                allow_sensors: true,
                allow_camera: true,
                allow_microphone: true,
            },
            PolicyComponent::Audio => AccessCaps {
                memory_limit: Self::memory_limit(component),
                cpu_quota: Self::cpu_quota(component),
                allow_network: false,
                allow_storage: true,
                allow_sensors: false,
                allow_camera: false,
                allow_microphone: true,
            },
            PolicyComponent::Nfc => AccessCaps {
                memory_limit: Self::memory_limit(component),
                cpu_quota: Self::cpu_quota(component),
                allow_network: false,
                allow_storage: false,
                allow_sensors: false,
                allow_camera: false,
                allow_microphone: false,
            },
            PolicyComponent::Camera => AccessCaps {
                memory_limit: Self::memory_limit(component),
                cpu_quota: Self::cpu_quota(component),
                allow_network: false,
                allow_storage: true,
                allow_sensors: true,
                allow_camera: true,
                allow_microphone: false,
            },
            PolicyComponent::Gps => AccessCaps {
                memory_limit: Self::memory_limit(component),
                cpu_quota: Self::cpu_quota(component),
                allow_network: false,
                allow_storage: false,
                allow_sensors: true,
                allow_camera: false,
                allow_microphone: false,
            },
        }
    }

    pub fn is_device_allowed(component: PolicyComponent, device: AccessDevice) -> bool {
        let caps = Self::allowed_devices(component);
        match device {
            AccessDevice::Network => caps.allow_network,
            AccessDevice::Storage => caps.allow_storage,
            AccessDevice::Sensors => caps.allow_sensors,
            AccessDevice::Camera => caps.allow_camera,
            AccessDevice::Microphone => caps.allow_microphone,
        }
    }
}

#[derive(Copy, Clone)]
pub enum PolicyComponent {
    Ia,
    Audio,
    Nfc,
    Camera,
    Gps,
}