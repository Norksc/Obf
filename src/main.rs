use crc32fast::Hasher as Crc32;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Write as FmtWrite;
use std::io::{self, Read};

const KEY_SEED: u32 = 0x5123_4567;

const CANONICAL_OPS: [OpCode; 8] = [
    OpCode::LoadK,
    OpCode::Move,
    OpCode::Add,
    OpCode::Sub,
    OpCode::Mul,
    OpCode::Div,
    OpCode::Return,
    OpCode::Halt,
];

const MAX_REGS: u8 = 32;
const REG_MASK: u8 = MAX_REGS - 1;
const IMM10_MIN: i32 = -512;
const IMM10_MAX: i32 = 511;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum OpCode {
    LoadK,
    Move,
    Add,
    Sub,
    Mul,
    Div,
    Return,
    Halt,
}

#[derive(Debug)]
struct DynamicOpcodeMap {
    forward: HashMap<OpCode, u8>,
}

impl DynamicOpcodeMap {
    fn new(seed: u64) -> Self {
        let mut ids: Vec<u8> = (0..64).collect();
        let mut rng = StdRng::seed_from_u64(seed);
        ids.shuffle(&mut rng);
        let mut forward = HashMap::new();
        for (op, opcode_id) in CANONICAL_OPS.into_iter().zip(ids.into_iter()) {
            forward.insert(op, opcode_id);
        }
        Self { forward }
    }

    fn get(&self, op: OpCode) -> u8 {
        *self.forward.get(&op).expect("opcode mapping missing")
    }
}

#[derive(Debug, Clone, Copy)]
enum Operand {
    Reg(u8),
    Imm(i32),
}

#[derive(Debug, Clone, Copy)]
enum InstrKind {
    LoadK {
        dst: u8,
        imm: i32,
    },
    Move {
        dst: u8,
        src: u8,
    },
    Bin {
        op: OpCode,
        dst: u8,
        a: u8,
        b: Operand,
    },
    Return {
        src: u8,
    },
    Halt,
}

#[derive(Default)]
struct Parser {
    symbols: HashMap<String, u8>,
    next_reg: u8,
}

impl Parser {
    fn new() -> Self {
        Self::default()
    }

    fn ensure_reg(&mut self, name: &str) -> Result<u8, Box<dyn Error>> {
        if let Some(&reg) = self.symbols.get(name) {
            Ok(reg)
        } else {
            if self.next_reg >= MAX_REGS {
                return Err(format!(
                    "register limit ({MAX_REGS}) exceeded while allocating '{name}'"
                )
                .into());
            }
            let reg = self.next_reg;
            self.next_reg += 1;
            self.symbols.insert(name.to_string(), reg);
            Ok(reg)
        }
    }

    fn ensure_reg_with_new(&mut self, name: &str) -> Result<(u8, bool), Box<dyn Error>> {
        if let Some(&reg) = self.symbols.get(name) {
            Ok((reg, false))
        } else {
            if self.next_reg >= MAX_REGS {
                return Err(format!(
                    "register limit ({MAX_REGS}) exceeded while allocating '{name}'"
                )
                .into());
            }
            let reg = self.next_reg;
            self.next_reg += 1;
            self.symbols.insert(name.to_string(), reg);
            Ok((reg, true))
        }
    }

    fn parse_operand(&mut self, token: &str) -> Result<Operand, Box<dyn Error>> {
        if let Ok(num) = token.parse::<i32>() {
            Ok(Operand::Imm(num))
        } else {
            Ok(Operand::Reg(self.ensure_reg(token)?))
        }
    }

    fn parse_line(&mut self, line: &str) -> Result<Vec<InstrKind>, Box<dyn Error>> {
        let trimmed = line.trim();
        let mut out = Vec::new();
        if trimmed.is_empty() {
            return Ok(out);
        }
        if trimmed.starts_with("return ") {
            let name = trimmed.strip_prefix("return ").unwrap().trim();
            let reg = self.ensure_reg(name)?;
            out.push(InstrKind::Return { src: reg });
            return Ok(out);
        }
        if trimmed == "halt" {
            out.push(InstrKind::Halt);
            return Ok(out);
        }

        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let lhs_clean = lhs.trim().trim_start_matches("local ").trim();
            let dest = self.ensure_reg(lhs_clean)?;
            let expr = rhs.trim();
            if let Some((a, op_sym, b)) = Self::split_binary(expr) {
                let a_operand = self.parse_operand(a)?;
                let b_operand = self.parse_operand(b)?;
                let a_reg = match a_operand {
                    Operand::Reg(r) => r,
                    Operand::Imm(val) => {
                        let (reg, is_new) =
                            self.ensure_reg_with_new(&format!("__const_lhs_{}", val))?;
                        if is_new {
                            out.push(InstrKind::LoadK { dst: reg, imm: val });
                        }
                        reg
                    }
                };
                let op = match op_sym {
                    "+" => OpCode::Add,
                    "-" => OpCode::Sub,
                    "*" => OpCode::Mul,
                    "/" => OpCode::Div,
                    _ => return Err("unsupported binary op".into()),
                };
                out.push(InstrKind::Bin {
                    op,
                    dst: dest,
                    a: a_reg,
                    b: b_operand,
                });
                return Ok(out);
            }
            let operand = self.parse_operand(expr)?;
            match operand {
                Operand::Imm(val) => out.push(InstrKind::LoadK {
                    dst: dest,
                    imm: val,
                }),
                Operand::Reg(src) => out.push(InstrKind::Move { dst: dest, src }),
            }
            return Ok(out);
        }

        Err(format!("Unable to parse line: {trimmed}").into())
    }

    fn split_binary(expr: &str) -> Option<(&str, &str, &str)> {
        for op in ["+", "-", "*", "/"] {
            if let Some((a, b)) = expr.split_once(op) {
                return Some((a.trim(), op, b.trim()));
            }
        }
        None
    }

    fn parse_program(&mut self, input: &str) -> Result<Vec<InstrKind>, Box<dyn Error>> {
        let mut instructions = Vec::new();
        for line in input.lines() {
            instructions.extend(self.parse_line(line)?);
        }
        instructions.push(InstrKind::Halt);
        Ok(instructions)
    }
}

struct BitWriter {
    data: Vec<u8>,
    acc: u8,
    used: u8,
    total_bits: usize,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            data: Vec::new(),
            acc: 0,
            used: 0,
            total_bits: 0,
        }
    }

    fn write_bits(&mut self, value: u64, width: u8) {
        for i in (0..width).rev() {
            let bit = ((value >> i) & 1) as u8;
            self.acc |= bit << (7 - self.used);
            self.used += 1;
            self.total_bits += 1;
            if self.used == 8 {
                self.data.push(self.acc);
                self.acc = 0;
                self.used = 0;
            }
        }
    }

    fn finalize(mut self) -> (Vec<u8>, usize) {
        if self.used > 0 {
            self.data.push(self.acc);
        }
        (self.data, self.total_bits)
    }
}

struct EncodedProgram {
    bytes: Vec<u8>,
    total_bits: usize,
}

impl EncodedProgram {
    fn to_hex_string(&self) -> String {
        let mut out = String::new();
        for (i, byte) in self.bytes.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            write!(&mut out, "{:02X}", byte).unwrap();
        }
        out
    }
}

struct CipheredProgram {
    ciphertext: Vec<u8>,
    total_bits: usize,
    crc32: u32,
    key: u64,
}

struct XorShift32 {
    state: u32,
}

impl XorShift32 {
    fn new(seed: u32) -> Self {
        let init = seed ^ KEY_SEED;
        Self {
            state: (init | 1) & 0xFFFF_FFFF,
        }
    }

    fn next(&mut self) -> u32 {
        self.state ^= self.state << 7;
        self.state ^= self.state >> 9;
        self.state ^= self.state << 8;
        self.state &= 0xFFFF_FFFF;
        self.state
    }

    fn next_byte(&mut self) -> u8 {
        (self.next() & 0xFF) as u8
    }
}

fn ensure_reg_bits(reg: u8) -> Result<u8, Box<dyn Error>> {
    if reg < MAX_REGS {
        Ok(reg & REG_MASK)
    } else {
        Err(format!("register {reg} exceeds encodable limit {REG_MASK}").into())
    }
}

fn ensure_imm10(value: i32) -> Result<u16, Box<dyn Error>> {
    if value < IMM10_MIN || value > IMM10_MAX {
        Err(format!("immediate {value} out of encodable range [{IMM10_MIN}, {IMM10_MAX}]").into())
    } else {
        Ok(((value as i16) as u16) & 0x03FF)
    }
}

fn encode_program(
    instructions: &[InstrKind],
    mapping: &DynamicOpcodeMap,
) -> Result<EncodedProgram, Box<dyn Error>> {
    let mut writer = BitWriter::new();
    writer.write_bits(CANONICAL_OPS.len() as u64, 6);
    for op in CANONICAL_OPS {
        writer.write_bits(mapping.get(op) as u64, 6);
    }

    for instr in instructions {
        match *instr {
            InstrKind::LoadK { dst, imm } => {
                writer.write_bits(mapping.get(OpCode::LoadK) as u64, 6);
                writer.write_bits(1, 1);
                writer.write_bits(ensure_reg_bits(dst)? as u64, 5);
                writer.write_bits(0, 5);
                writer.write_bits(ensure_imm10(imm)? as u64, 10);
            }
            InstrKind::Move { dst, src } => {
                writer.write_bits(mapping.get(OpCode::Move) as u64, 6);
                writer.write_bits(0, 1);
                writer.write_bits(ensure_reg_bits(dst)? as u64, 5);
                writer.write_bits(ensure_reg_bits(src)? as u64, 5);
                writer.write_bits(0, 5);
            }
            InstrKind::Bin { op, dst, a, b } => match b {
                Operand::Reg(rb) => {
                    writer.write_bits(mapping.get(op) as u64, 6);
                    writer.write_bits(0, 1);
                    writer.write_bits(ensure_reg_bits(dst)? as u64, 5);
                    writer.write_bits(ensure_reg_bits(a)? as u64, 5);
                    writer.write_bits(ensure_reg_bits(rb)? as u64, 5);
                }
                Operand::Imm(imm) => {
                    writer.write_bits(mapping.get(op) as u64, 6);
                    writer.write_bits(1, 1);
                    writer.write_bits(ensure_reg_bits(dst)? as u64, 5);
                    writer.write_bits(ensure_reg_bits(a)? as u64, 5);
                    writer.write_bits(ensure_imm10(imm)? as u64, 10);
                }
            },
            InstrKind::Return { src } => {
                writer.write_bits(mapping.get(OpCode::Return) as u64, 6);
                writer.write_bits(0, 1);
                writer.write_bits(ensure_reg_bits(src)? as u64, 5);
                writer.write_bits(0, 5);
                writer.write_bits(0, 5);
            }
            InstrKind::Halt => {
                writer.write_bits(mapping.get(OpCode::Halt) as u64, 6);
                writer.write_bits(0, 1);
                writer.write_bits(0, 5);
                writer.write_bits(0, 5);
                writer.write_bits(0, 5);
            }
        }
    }

    let (bytes, total_bits) = writer.finalize();
    Ok(EncodedProgram { bytes, total_bits })
}

fn obfuscate_program(encoded: EncodedProgram, seed: u32) -> CipheredProgram {
    let mut keystream = XorShift32::new(seed);
    let mut crc = Crc32::new();
    let mut ciphertext = Vec::with_capacity(encoded.bytes.len());
    for &byte in encoded.bytes.iter() {
        let k = keystream.next_byte();
        let obf = byte ^ k;
        crc.update(&[obf]);
        ciphertext.push(obf);
    }
    CipheredProgram {
        ciphertext,
        total_bits: encoded.total_bits,
        crc32: crc.finalize(),
        key: (seed ^ KEY_SEED) as u64,
    }
}

fn compile(input: &str, seed: u32) -> Result<(CipheredProgram, DynamicOpcodeMap), Box<dyn Error>> {
    let mut parser = Parser::new();
    let program = parser.parse_program(input)?;
    let mapping = DynamicOpcodeMap::new(seed);
    let encoded = encode_program(&program, &mapping)?;
    let ciphered = obfuscate_program(encoded, seed);
    Ok((ciphered, mapping))
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    if input.trim().is_empty() {
        input = DEFAULT_SAMPLE.to_string();
    }

    let seed: u32 = 0x0BAD_5EED;
    let (ciphered, mapping) = compile(&input, seed)?;

    println!(";; Dynamic opcode map (canonical -> randomized id)");
    for op in CANONICAL_OPS {
        println!("{:?} => {}", op, mapping.get(op));
    }

    println!(
        "\n;; Obfuscated program ({} bits, {} bytes)",
        ciphered.total_bits,
        ciphered.ciphertext.len()
    );
    println!(";; XOR keystream key: 0x{:016X}", ciphered.key);
    println!(";; CRC32 of ciphertext: 0x{:08X}", ciphered.crc32);
    println!(
        "{}",
        EncodedProgram {
            bytes: ciphered.ciphertext.clone(),
            total_bits: ciphered.total_bits
        }
        .to_hex_string()
    );

    Ok(())
}

const DEFAULT_SAMPLE: &str = r#"
local a = 3
local b = 9
c = a + b
return c
"#;
