use crate::prelude::Vec;

pub struct WasmCompiler {
    bytecode: Vec<u8>,
}

impl WasmCompiler {
    pub fn new() -> Self {
        WasmCompiler {
            bytecode: Vec::new(),
        }
    }

    pub fn compile(&mut self, source: &[u8]) -> Result<Vec<u8>, &'static str> {
        self.bytecode.clear();
        
        if source.is_empty() {
            return Err("Empty source");
        }

        // Magic + version
        self.bytecode.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d]);
        self.bytecode.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);

        // Custom section with source
        let mut custom = Vec::new();
        push_leb_u32(&mut custom, 6); // name length
        custom.extend_from_slice(b"source");
        custom.extend_from_slice(source);
        push_section(&mut self.bytecode, 0x00, &custom);

        // Type section: one function type () -> ()
        let mut types = Vec::new();
        push_leb_u32(&mut types, 1);
        types.push(0x60);
        types.push(0x00);
        types.push(0x00);
        push_section(&mut self.bytecode, 0x01, &types);

        // Function section: one function, type 0
        let mut funcs = Vec::new();
        push_leb_u32(&mut funcs, 1);
        funcs.push(0x00);
        push_section(&mut self.bytecode, 0x03, &funcs);

        // Code section: one empty body
        let mut code = Vec::new();
        push_leb_u32(&mut code, 1);
        let mut body = Vec::new();
        body.push(0x00); // locals count
        body.push(0x0b); // end
        push_leb_u32(&mut code, body.len() as u32);
        code.extend_from_slice(&body);
        push_section(&mut self.bytecode, 0x0a, &code);

        Ok(self.bytecode.clone())
    }

    pub fn validate(&self, bytecode: &[u8]) -> bool {
        bytecode.len() >= 8
            && bytecode[0..4] == [0x00, 0x61, 0x73, 0x6d]
            && bytecode[4..8] == [0x01, 0x00, 0x00, 0x00]
    }

    pub fn get_bytecode(&self) -> &[u8] {
        &self.bytecode
    }
}

fn push_section(out: &mut Vec<u8>, id: u8, content: &[u8]) {
    out.push(id);
    push_leb_u32(out, content.len() as u32);
    out.extend_from_slice(content);
}

fn push_leb_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}
