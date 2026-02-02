
use crate::identity::auth::Auth;
use crate::permissions::policy::{Policy, PolicyComponent, AccessDevice};
use crate::DriverError;

pub struct AccessControl;

impl AccessControl {
    pub fn check_access(
        component: PolicyComponent,
        device: AccessDevice,
        context: &[u8],
    ) -> Result<(), DriverError> {
        if !Auth::verify_access(context, None)? {
            return Err(DriverError::PermissionDenied);
        }

        if !Policy::is_device_allowed(component, device) {
            return Err(DriverError::PermissionDenied);
        }

        Ok(())
    }

    pub fn check_memory(component: PolicyComponent, requested_bytes: usize) -> Result<(), DriverError> {
        let caps = Policy::allowed_devices(component);
        if requested_bytes > caps.memory_limit {
            return Err(DriverError::ResourceLimit);
        }
        Ok(())
    }

    pub fn free_memory(bytes: usize) {
        let _ = bytes;
    }

    pub fn check_cpu(component: PolicyComponent, current_usage: u8) -> Result<(), DriverError> {
        let quota = Policy::cpu_quota(component);
        if current_usage > quota {
            return Err(DriverError::ResourceLimit);
        }
        Ok(())
    }

}