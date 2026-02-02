use crate::prelude::{String, Vec};

pub struct WasmTranspiler {
    opcodes: Vec<String>,
}

impl WasmTranspiler {
    pub fn new() -> Self {
        WasmTranspiler {
            opcodes: Vec::new(),
        }
    }

    pub fn transpile(&mut self, wasm_bytecode: &[u8]) -> Result<Vec<String>, &'static str> {
        self.opcodes.clear();

        for byte in wasm_bytecode {
            let opcode = match byte {
                0x20 => "local.get",
                0x21 => "local.set",
                0x41 => "i32.const",
                0x6a => "i32.add",
                0x6b => "i32.sub",
                0x6c => "i32.mul",
                0x6d => "i32.div_s",
                0x0b => "end",
                _ => "unknown",
            };
            self.opcodes.push(String::from(opcode));
        }

        Ok(self.opcodes.clone())
    }

    pub fn get_ir(&self) -> &[String] {
        &self.opcodes
    }
}
