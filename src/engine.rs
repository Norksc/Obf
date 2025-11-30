use std::collections::{HashMap, HashSet};

use aes_gcm::{aead::Aead, aead::KeyInit, Aes256Gcm, Nonce};
use base64::{engine::general_purpose, Engine as _};
use rand::rngs::{OsRng, StdRng};
use rand::seq::SliceRandom;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("encryption error: {0}")]
    Encrypt(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Opcode {
    Move,
    LoadK,
    Add,
    Sub,
    Mul,
    Div,
    Jump,
    Return,
    Nop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instruction {
    pub opcode: u8,
    pub a: i32,
    pub b: i32,
    pub c: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bytecode {
    pub opcode_map: HashMap<Opcode, u8>,
    pub code: Vec<Instruction>,
    pub string_table: Vec<String>,
    pub control_state_slots: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedPayload {
    pub bytecode: Bytecode,
    pub encrypted_strings: String,
    pub nonce: String,
    pub opaque_key: String,
    pub stats: ProtectStats,
    pub guard: GuardArtifacts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectStats {
    pub junk_injected: usize,
    pub flattened_blocks: usize,
    pub string_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardArtifacts {
    pub checksum: u64,
    pub polymorph_seed: u64,
    pub decoy_pool: usize,
}

#[derive(Debug, Clone)]
pub struct Ast {
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone)]
pub enum Expr {
    Number(f64),
    Var(String),
    BinOp {
        op: char,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
}

#[derive(Debug, Clone)]
pub enum Stmt {
    Assign {
        name: String,
        expr: Expr,
    },
    If {
        cond: Expr,
        then_body: Vec<Stmt>,
        else_body: Vec<Stmt>,
    },
    Return(Expr),
}

/// Parse a minimal Lua subset to an AST.
pub fn parse_lua(input: &str) -> Result<Ast, EngineError> {
    let mut body = Vec::new();
    for line in input.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(rhs) = trimmed.strip_prefix("return ") {
            body.push(Stmt::Return(parse_expr(rhs.trim())?));
            continue;
        }
        if trimmed.starts_with("if ") && trimmed.contains(" then") {
            // ultra-compact single-line if a then return b else return c end
            let parts: Vec<&str> = trimmed
                .strip_prefix("if ")
                .unwrap()
                .split(" then ")
                .collect();
            if parts.len() != 2 || !parts[1].contains(" else ") {
                return Err(EngineError::Parse("unsupported if syntax".into()));
            }
            let cond = parse_expr(parts[0].trim())?;
            let halves: Vec<&str> = parts[1].split(" else ").collect();
            let then_expr = parse_expr(halves[0].trim())?;
            let else_expr = parse_expr(halves[1].trim().trim_end_matches(" end"))?;
            body.push(Stmt::If {
                cond,
                then_body: vec![Stmt::Return(then_expr.clone())],
                else_body: vec![Stmt::Return(else_expr.clone())],
            });
            continue;
        }
        if let Some((lhs, rhs)) = trimmed.split_once('=') {
            body.push(Stmt::Assign {
                name: lhs.trim().to_string(),
                expr: parse_expr(rhs.trim())?,
            });
            continue;
        }
        return Err(EngineError::Parse(format!("unrecognized line: {trimmed}")));
    }
    Ok(Ast { body })
}

fn parse_expr(src: &str) -> Result<Expr, EngineError> {
    for op in ['+', '-', '*', '/'] {
        if let Some((lhs, rhs)) = split_once(src, op) {
            return Ok(Expr::BinOp {
                op,
                lhs: Box::new(parse_expr(lhs.trim())?),
                rhs: Box::new(parse_expr(rhs.trim())?),
            });
        }
    }
    if let Ok(num) = src.parse::<f64>() {
        return Ok(Expr::Number(num));
    }
    Ok(Expr::Var(src.to_string()))
}

fn split_once(hay: &str, needle: char) -> Option<(&str, &str)> {
    let mut depth = 0;
    for (idx, ch) in hay.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && ch == needle {
            return Some((&hay[..idx], &hay[idx + 1..]));
        }
    }
    None
}

fn fold_constants(expr: Expr) -> Expr {
    match expr {
        Expr::BinOp { op, lhs, rhs } => {
            let l = fold_constants(*lhs);
            let r = fold_constants(*rhs);
            if let (Expr::Number(a), Expr::Number(b)) = (&l, &r) {
                let val = match op {
                    '+' => a + b,
                    '-' => a - b,
                    '*' => a * b,
                    '/' => a / b,
                    _ => *a,
                };
                Expr::Number(val)
            } else {
                Expr::BinOp {
                    op,
                    lhs: Box::new(l),
                    rhs: Box::new(r),
                }
            }
        }
        other => other,
    }
}

fn collect_strings(ast: &Ast) -> Vec<String> {
    let mut set = HashSet::new();
    for stmt in &ast.body {
        match stmt {
            Stmt::Assign { name, .. } => {
                set.insert(name.clone());
            }
            Stmt::Return(_) => {}
            Stmt::If { .. } => {}
        }
    }
    set.into_iter().collect()
}

fn random_opcode_map() -> HashMap<Opcode, u8> {
    let mut rng = rand::thread_rng();
    let mut available: Vec<u8> = (1..=250).collect();
    available.shuffle(&mut rng);
    let mut map = HashMap::new();
    for op in [
        Opcode::Move,
        Opcode::LoadK,
        Opcode::Add,
        Opcode::Sub,
        Opcode::Mul,
        Opcode::Div,
        Opcode::Jump,
        Opcode::Return,
        Opcode::Nop,
    ] {
        let id = available.pop().unwrap();
        map.insert(op, id);
    }
    map
}

fn flatten_control_flow(ast: &Ast) -> (Vec<Instruction>, usize) {
    let map = random_opcode_map();
    let mut code = Vec::new();
    let mut state = 0;
    for stmt in &ast.body {
        match stmt {
            Stmt::Assign { name, expr } => {
                let dest = hash_reg(name);
                let expr_folded = fold_constants(expr.clone());
                emit_expr(&map, &mut code, dest as i32, expr_folded);
            }
            Stmt::Return(expr) => {
                let folded = fold_constants(expr.clone());
                emit_expr(&map, &mut code, 0, folded);
                code.push(Instruction {
                    opcode: *map.get(&Opcode::Return).unwrap(),
                    a: 0,
                    b: 0,
                    c: 0,
                });
            }
            Stmt::If {
                cond,
                then_body,
                else_body,
            } => {
                // Control-flow flatten: predicate writes to state variable, loop dispatches.
                let predicate_reg = 250;
                emit_expr(&map, &mut code, predicate_reg, fold_constants(cond.clone()));
                code.push(Instruction {
                    opcode: *map.get(&Opcode::Jump).unwrap(),
                    a: predicate_reg,
                    b: (state + 1) as i32,
                    c: (state + 2) as i32,
                });
                let then_code = flatten_block(&map, then_body);
                code.extend_from_slice(&then_code);
                code.push(Instruction {
                    opcode: *map.get(&Opcode::Jump).unwrap(),
                    a: 1,
                    b: (state + 3) as i32,
                    c: (state + 3) as i32,
                });
                let else_code = flatten_block(&map, else_body);
                code.extend_from_slice(&else_code);
                state += 3;
            }
        }
    }
    code.push(Instruction {
        opcode: *map.get(&Opcode::Nop).unwrap(),
        a: 0,
        b: 0,
        c: 0,
    });
    (code, state + 1)
}

fn flatten_block(map: &HashMap<Opcode, u8>, body: &[Stmt]) -> Vec<Instruction> {
    let mut code = Vec::new();
    for stmt in body {
        match stmt {
            Stmt::Assign { name, expr } => {
                let dest = hash_reg(name);
                emit_expr(map, &mut code, dest as i32, fold_constants(expr.clone()));
            }
            Stmt::Return(expr) => {
                emit_expr(map, &mut code, 0, fold_constants(expr.clone()));
                code.push(Instruction {
                    opcode: *map.get(&Opcode::Return).unwrap(),
                    a: 0,
                    b: 0,
                    c: 0,
                });
            }
            Stmt::If { .. } => {}
        }
    }
    code
}

fn hash_reg(name: &str) -> u8 {
    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    digest[0]
}

fn emit_expr(map: &HashMap<Opcode, u8>, out: &mut Vec<Instruction>, dest: i32, expr: Expr) {
    match expr {
        Expr::Number(v) => out.push(Instruction {
            opcode: *map.get(&Opcode::LoadK).unwrap(),
            a: dest,
            b: v.to_bits() as i32,
            c: 0,
        }),
        Expr::Var(name) => out.push(Instruction {
            opcode: *map.get(&Opcode::Move).unwrap(),
            a: dest,
            b: hash_reg(&name) as i32,
            c: 0,
        }),
        Expr::BinOp { op, lhs, rhs } => {
            let tmp_left = dest + 1;
            let tmp_right = dest + 2;
            emit_expr(map, out, tmp_left, *lhs);
            emit_expr(map, out, tmp_right, *rhs);
            let opcode = match op {
                '+' => Opcode::Add,
                '-' => Opcode::Sub,
                '*' => Opcode::Mul,
                '/' => Opcode::Div,
                _ => Opcode::Add,
            };
            out.push(Instruction {
                opcode: *map.get(&opcode).unwrap(),
                a: dest,
                b: tmp_left,
                c: tmp_right,
            });
        }
    }
}

fn inject_junk(map: &HashMap<Opcode, u8>, code: &mut Vec<Instruction>, count: usize) -> usize {
    let before = code.len();
    for i in 0..count {
        code.insert(
            (i * 3) % (code.len().saturating_sub(1).max(1)),
            Instruction {
                opcode: *map.get(&Opcode::Nop).unwrap(),
                a: i as i32,
                b: (i as i32).wrapping_mul(7),
                c: 0,
            },
        );
    }
    code.len() - before
}

fn insert_control_noise(
    map: &HashMap<Opcode, u8>,
    code: &mut Vec<Instruction>,
    polymorph_seed: u64,
) {
    let mut rng = rand::rngs::StdRng::seed_from_u64(polymorph_seed);
    // Walk the code and inject pseudo-random state swaps that keep behavior neutral.
    for (idx, slot) in code.iter().enumerate() {
        let wobble = rng.next_u64() as i32;
        if idx % 5 == 0 {
            code.insert(
                idx,
                Instruction {
                    opcode: *map.get(&Opcode::Move).unwrap(),
                    a: slot.a ^ (wobble & 0xFF) as i32,
                    b: slot.a,
                    c: 0,
                },
            );
        }
    }
}

fn encrypt_strings(strings: &[String]) -> Result<(String, String, String), EngineError> {
    let key = {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes
    };
    let nonce_bytes = {
        let mut b = [0u8; 12];
        OsRng.fill_bytes(&mut b);
        b
    };
    let cipher =
        Aes256Gcm::new_from_slice(&key).map_err(|e| EngineError::Encrypt(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let serialized =
        serde_json::to_vec(strings).map_err(|e| EngineError::Encrypt(e.to_string()))?;
    let ciphertext = cipher
        .encrypt(nonce, serialized.as_ref())
        .map_err(|e| EngineError::Encrypt(e.to_string()))?;
    Ok((
        general_purpose::STANDARD.encode(ciphertext),
        general_purpose::STANDARD.encode(key),
        general_purpose::STANDARD.encode(nonce_bytes),
    ))
}

fn checksum_instructions(code: &[Instruction], strings: &[String]) -> u64 {
    let mut acc: u64 = 0xA5A5_5A5A_F0F0_C3C3;
    for inst in code {
        acc = acc
            .wrapping_add(inst.opcode as u64)
            .wrapping_mul(0x9E37_79B9)
            ^ (inst.a as u64).rotate_left(13)
            ^ (inst.b as u64).rotate_right(7)
            ^ (inst.c as u64).rotate_left(3);
    }
    for s in strings {
        for b in s.as_bytes() {
            acc = acc.wrapping_add(*b as u64).rotate_left(9) ^ 0xDEADBEEFCAFEBABEu64;
        }
    }
    acc
}

pub fn protect_script(
    bytes: Vec<u8>,
    level: crate::ProtectionLevel,
) -> Result<ProtectedPayload, EngineError> {
    let source = String::from_utf8_lossy(&bytes);
    let ast = parse_lua(&source)?;
    let strings = collect_strings(&ast);
    let (mut code, state_slots) = flatten_control_flow(&ast);
    let opcode_map = random_opcode_map();
    let junk = match level {
        crate::ProtectionLevel::Light => 1,
        crate::ProtectionLevel::Default => 3,
        crate::ProtectionLevel::Heavy => 6,
    };
    let junk_injected = inject_junk(&opcode_map, &mut code, junk);
    let polymorph_seed = {
        let mut seed_bytes = [0u8; 8];
        OsRng.fill_bytes(&mut seed_bytes);
        u64::from_le_bytes(seed_bytes)
    };
    insert_control_noise(&opcode_map, &mut code, polymorph_seed);
    let (encrypted_strings, opaque_key, nonce) = encrypt_strings(&strings)?;

    let bytecode = Bytecode {
        opcode_map: opcode_map.clone(),
        code,
        string_table: strings.clone(),
        control_state_slots: state_slots,
    };

    let stats = ProtectStats {
        junk_injected,
        flattened_blocks: state_slots,
        string_count: strings.len(),
    };

    let guard = GuardArtifacts {
        checksum: checksum_instructions(&code, &strings),
        polymorph_seed,
        decoy_pool: strings.len().saturating_mul(2) + junk_injected,
    };

    Ok(ProtectedPayload {
        bytecode,
        encrypted_strings,
        nonce,
        opaque_key,
        stats,
        guard,
    })
}
