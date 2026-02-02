pub struct ZeroCopyParser<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ZeroCopyParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        ZeroCopyParser {
            data,
            offset: 0,
        }
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        if self.offset + 4 <= self.data.len() {
            let bytes = &self.data[self.offset..self.offset + 4];
            self.offset += 4;
            Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else {
            None
        }
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        if self.offset < self.data.len() {
            let byte = self.data[self.offset];
            self.offset += 1;
            Some(byte)
        } else {
            None
        }
    }

    pub fn read_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.offset + len <= self.data.len() {
            let slice = &self.data[self.offset..self.offset + len];
            self.offset += len;
            Some(slice)
        } else {
            None
        }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    pub fn position(&self) -> usize {
        self.offset
    }
}
