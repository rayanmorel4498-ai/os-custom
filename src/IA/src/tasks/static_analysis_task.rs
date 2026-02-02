use crate::prelude::{String, Vec};
use alloc::collections::BTreeMap;
use alloc::format;

pub struct StaticAnalyzer {
    functions: BTreeMap<String, usize>,
    variables: BTreeMap<String, String>,
    issues: Vec<String>,
}

impl StaticAnalyzer {
    pub fn new() -> Self {
        StaticAnalyzer {
            functions: BTreeMap::new(),
            variables: BTreeMap::new(),
            issues: Vec::new(),
        }
    }

    pub fn register_function(&mut self, name: String, complexity: usize) {
        self.functions.insert(name, complexity);
    }

    pub fn register_variable(&mut self, name: String, var_type: String) {
        self.variables.insert(name, var_type);
    }

    pub fn analyze_complexity(&mut self) {
        for (name, complexity) in &self.functions {
            if *complexity > 10 {
                self.issues.push(format!("High complexity: {}", name));
            }
        }
    }

    pub fn get_issues(&self) -> &[String] {
        &self.issues
    }

    pub fn quality_score(&self) -> u8 {
        let max_score = 100u8;
        let deduction = (self.issues.len() as u8) * 5;
        if deduction > max_score {
            0
        } else {
            max_score - deduction
        }
    }
}
