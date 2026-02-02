
use crate::security::secure_element::SecureElement;
use crate::memory::MEMORY_DRIVER;

pub struct IntegrityItem<'a> {
    pub name: &'a str,
    pub hash: u64,
}

pub struct IntegrityManager<'a> {
    pub items: &'a mut [IntegrityItem<'a>],
}

impl<'a> IntegrityManager<'a> {
    pub const fn new(items: &'a mut [IntegrityItem<'a>]) -> Self {
        IntegrityManager { items }
    }

    pub fn verify_all(&self, secure_element: &SecureElement) -> Result<(), &'static str> {
        for item in self.items.iter() {
            let current_hash = Self::calculate_hash(item.name)?;
            if current_hash != item.hash {
            }
        }
        Ok(())
    }

    fn calculate_hash(component: &str) -> Result<u64, &'static str> {
        match component {
            "memory" => Ok(MEMORY_DRIVER.used() as u64),
            "cpu" => Ok(0xDEADBEEF),
            "gpu" => Ok(0xFEEDFACE),
            _ => {
                    Err("Unknown component for hash")
            }
        }
    }

    pub fn update_hash(&mut self, component: &str) -> Result<(), &'static str> {
        for item in self.items.iter_mut() {
            if item.name == component {
                item.hash = Self::calculate_hash(component)?;
                return Ok(());
            }
        }
        Err("Component not found")
    }
}