use crc32fast::Hasher as Crc32;
use rand::seq::SliceRandom;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::{HashMap, HashSet};
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

#[derive(Debug, Clone)]
enum Expr {
    Imm(i32),
    Var(String),
    Bin {
        op: OpCode,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
}

#[derive(Debug, Clone)]
enum Stmt {
    Assign { name: String, expr: Expr },
    Return(String),
    Halt,
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
struct Parser;

impl Parser {
    fn new() -> Self {
        Self::default()
    }

    fn parse_operand(token: &str) -> Result<Expr, Box<dyn Error>> {
        if let Ok(num) = token.parse::<i32>() {
            Ok(Expr::Imm(num))
        } else {
            Ok(Expr::Var(token.trim().to_string()))
        }
    }

    fn parse_expr(expr: &str) -> Result<Expr, Box<dyn Error>> {
        if let Some((lhs, op, rhs)) = Self::split_binary(expr) {
            let lhs_expr = Self::parse_operand(lhs)?;
            let rhs_expr = Self::parse_operand(rhs)?;
            let op = match op {
                "+" => OpCode::Add,
                "-" => OpCode::Sub,
                "*" => OpCode::Mul,
                "/" => OpCode::Div,
                _ => return Err("unsupported binary op".into()),
            };
            Ok(Expr::Bin {
                op,
                lhs: Box::new(lhs_expr),
                rhs: Box::new(rhs_expr),
            })
        } else {
            Self::parse_operand(expr)
        }
    }

    fn parse_line(line: &str) -> Result<Option<Stmt>, Box<dyn Error>> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        if trimmed.starts_with("return ") {
            let name = trimmed.strip_prefix("return ").unwrap().trim();
            return Ok(Some(Stmt::Return(name.to_string())));
        }
        if trimmed == "halt" {
            return Ok(Some(Stmt::Halt));
        }

        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            let lhs_clean = lhs.trim().trim_start_matches("local ").trim();
            let expr = Self::parse_expr(rhs.trim())?;
            return Ok(Some(Stmt::Assign {
                name: lhs_clean.to_string(),
                expr,
            }));
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

    fn parse_program(&mut self, input: &str) -> Result<Vec<Stmt>, Box<dyn Error>> {
        let mut stmts = Vec::new();
        for line in input.lines() {
            if let Some(stmt) = Self::parse_line(line)? {
                stmts.push(stmt);
            }
        }
        stmts.push(Stmt::Halt);
        Ok(stmts)
    }
}

struct BitWriter {
    data: Vec<u8>,
    acc: u8,
    used: u8,
    total_bits: usize,
}

fn constant_fold(expr: Expr) -> Expr {
    match expr {
        Expr::Bin { op, lhs, rhs } => {
            let lhs_f = constant_fold(*lhs);
            let rhs_f = constant_fold(*rhs);
            match (lhs_f.clone(), rhs_f.clone()) {
                (Expr::Imm(a), Expr::Imm(b)) => {
                    let val = match op {
                        OpCode::Add => a + b,
                        OpCode::Sub => a - b,
                        OpCode::Mul => a * b,
                        OpCode::Div => a / b,
                        _ => unreachable!(),
                    };
                    Expr::Imm(val)
                }
                _ => Expr::Bin {
                    op,
                    lhs: Box::new(lhs_f),
                    rhs: Box::new(rhs_f),
                },
            }
        }
        other => other,
    }
}

fn collect_uses(expr: &Expr, uses: &mut HashSet<String>) {
    match expr {
        Expr::Var(name) => {
            uses.insert(name.clone());
        }
        Expr::Bin { lhs, rhs, .. } => {
            collect_uses(lhs, uses);
            collect_uses(rhs, uses);
        }
        Expr::Imm(_) => {}
    }
}

fn dead_code_eliminate(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut needed: HashSet<String> = HashSet::new();
    let mut out = Vec::new();
    for stmt in stmts.into_iter().rev() {
        match stmt {
            Stmt::Return(name) => {
                needed.insert(name.clone());
                out.push(Stmt::Return(name));
            }
            Stmt::Assign { name, expr } => {
                if needed.contains(&name) {
                    let mut uses = HashSet::new();
                    collect_uses(&expr, &mut uses);
                    needed.remove(&name);
                    needed.extend(uses);
                    out.push(Stmt::Assign { name, expr });
                }
            }
            Stmt::Halt => out.push(Stmt::Halt),
        }
    }
    out.reverse();
    out
}

#[derive(Default)]
struct LowerCtx {
    symbols: HashMap<String, u8>,
    const_pool: HashMap<i32, u8>,
    next_reg: u8,
}

impl LowerCtx {
    fn alloc_reg(&mut self) -> Result<u8, Box<dyn Error>> {
        if self.next_reg >= MAX_REGS {
            return Err(format!("register limit ({MAX_REGS}) exceeded").into());
        }
        let reg = self.next_reg;
        self.next_reg += 1;
        Ok(reg)
    }

    fn ensure_var(&mut self, name: &str) -> Result<u8, Box<dyn Error>> {
        if let Some(&reg) = self.symbols.get(name) {
            Ok(reg)
        } else {
            let reg = self.alloc_reg()?;
            self.symbols.insert(name.to_string(), reg);
            Ok(reg)
        }
    }

    fn ensure_const(
        &mut self,
        imm: i32,
        instructions: &mut Vec<InstrKind>,
    ) -> Result<u8, Box<dyn Error>> {
        if let Some(&reg) = self.const_pool.get(&imm) {
            return Ok(reg);
        }
        let reg = self.alloc_reg()?;
        self.const_pool.insert(imm, reg);
        instructions.push(InstrKind::LoadK { dst: reg, imm });
        Ok(reg)
    }
}

fn lower_expr(
    expr: Expr,
    target: u8,
    ctx: &mut LowerCtx,
    instructions: &mut Vec<InstrKind>,
) -> Result<(), Box<dyn Error>> {
    match expr {
        Expr::Imm(v) => {
            instructions.push(InstrKind::LoadK {
                dst: target,
                imm: v,
            });
        }
        Expr::Var(name) => {
            let src = ctx
                .symbols
                .get(&name)
                .copied()
                .ok_or_else(|| format!("use of undefined symbol '{name}'"))?;
            if src != target {
                instructions.push(InstrKind::Move { dst: target, src });
            }
        }
        Expr::Bin { op, lhs, rhs } => {
            let a_reg = match *lhs {
                Expr::Imm(v) => ctx.ensure_const(v, instructions)?,
                Expr::Var(name) => ctx
                    .symbols
                    .get(&name)
                    .copied()
                    .ok_or_else(|| format!("use of undefined symbol '{name}'"))?,
                Expr::Bin { .. } => {
                    let reg = ctx.alloc_reg()?;
                    lower_expr(*lhs, reg, ctx, instructions)?;
                    reg
                }
            };
            let b_operand = match *rhs {
                Expr::Imm(v) => Operand::Imm(v),
                Expr::Var(name) => {
                    let reg = ctx
                        .symbols
                        .get(&name)
                        .copied()
                        .ok_or_else(|| format!("use of undefined symbol '{name}'"))?;
                    Operand::Reg(reg)
                }
                Expr::Bin { .. } => {
                    let reg = ctx.alloc_reg()?;
                    lower_expr(*rhs, reg, ctx, instructions)?;
                    Operand::Reg(reg)
                }
            };
            instructions.push(InstrKind::Bin {
                op,
                dst: target,
                a: a_reg,
                b: b_operand,
            });
        }
    }
    Ok(())
}

fn lower_program(stmts: Vec<Stmt>) -> Result<Vec<InstrKind>, Box<dyn Error>> {
    let mut instructions = Vec::new();
    let mut ctx = LowerCtx::default();
    for stmt in stmts {
        match stmt {
            Stmt::Assign { name, expr } => {
                let expr = constant_fold(expr);
                let dst = ctx.ensure_var(&name)?;
                lower_expr(expr, dst, &mut ctx, &mut instructions)?;
            }
            Stmt::Return(name) => {
                let src = ctx
                    .symbols
                    .get(&name)
                    .copied()
                    .ok_or_else(|| format!("use of undefined symbol '{name}'"))?;
                instructions.push(InstrKind::Return { src });
            }
            Stmt::Halt => instructions.push(InstrKind::Halt),
        }
    }
    Ok(instructions)
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
    let ast = parser.parse_program(input)?;
    let ast = ast.into_iter().map(|s| match s {
        Stmt::Assign { name, expr } => Stmt::Assign {
            name,
            expr: constant_fold(expr),
        },
        other => other,
    });
    let ast = dead_code_eliminate(ast.collect());
    let program = lower_program(ast)?;
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
