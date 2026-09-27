use crate::keccak::{AP_DONE_FOR_SIM, AP_IDLE_FOR_SIM, CONTROL, RETURN, RegisterIo};
use std::collections::BTreeMap;

#[derive(Default)]
pub struct SimulatedKeccak {
    registers: BTreeMap<usize, u32>,
    pub writes: Vec<(usize, u32)>,
    completion: Completion,
}
#[derive(Default)]
pub enum Completion {
    #[default]
    Success,
    Error(i32),
    Never,
}
impl SimulatedKeccak {
    pub fn success() -> Self {
        Self::default()
    }
    pub fn error(code: i32) -> Self {
        Self {
            completion: Completion::Error(code),
            ..Self::default()
        }
    }
    pub fn never_completes() -> Self {
        Self {
            completion: Completion::Never,
            ..Self::default()
        }
    }
}
impl RegisterIo for SimulatedKeccak {
    fn read32(&mut self, offset: usize) -> u32 {
        if offset == CONTROL && !self.registers.contains_key(&CONTROL) {
            AP_IDLE_FOR_SIM
        } else {
            *self.registers.get(&offset).unwrap_or(&0)
        }
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.writes.push((offset, value));
        self.registers.insert(offset, value);
        if offset == CONTROL && value & 1 != 0 {
            match self.completion {
                Completion::Success => {
                    self.registers.insert(RETURN, 0);
                    self.registers
                        .insert(CONTROL, AP_DONE_FOR_SIM | AP_IDLE_FOR_SIM);
                }
                Completion::Error(code) => {
                    self.registers.insert(RETURN, code as u32);
                    self.registers
                        .insert(CONTROL, AP_DONE_FOR_SIM | AP_IDLE_FOR_SIM);
                }
                Completion::Never => {
                    self.registers.insert(CONTROL, 0);
                }
            }
        }
    }
}
