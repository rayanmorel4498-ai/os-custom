pub struct SafetyChecker {
    warnings: u32,
    errors: u32,
}

impl SafetyChecker {
    pub fn new() -> Self {
        SafetyChecker {
            warnings: 0,
            errors: 0,
        }
    }

    pub fn check_bounds(&mut self, index: usize, len: usize) -> bool {
        if index >= len {
            self.errors += 1;
            false
        } else {
            true
        }
    }

    pub fn check_null(&mut self, ptr: *const u8) -> bool {
        if ptr.is_null() {
            self.errors += 1;
            false
        } else {
            true
        }
    }

    pub fn check_alignment(&mut self, ptr: *const u8, alignment: usize) -> bool {
        if (ptr as usize) % alignment != 0 {
            self.warnings += 1;
            false
        } else {
            true
        }
    }

    pub fn get_errors(&self) -> u32 {
        self.errors
    }

    pub fn get_warnings(&self) -> u32 {
        self.warnings
    }

    pub fn is_safe(&self) -> bool {
        self.errors == 0
    }
}
