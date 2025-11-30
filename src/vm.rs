use crate::engine::{Bytecode, ProtectedPayload};
use base64::{engine::general_purpose, Engine as _};

fn encode_opcode_map(map: &std::collections::HashMap<crate::engine::Opcode, u8>) -> String {
    let mut pairs: Vec<String> = map
        .iter()
        .map(|(op, id)| format!("{}:{}", format_opcode(op), id))
        .collect();
    pairs.sort();
    pairs.join(",")
}

fn format_opcode(op: &crate::engine::Opcode) -> &'static str {
    match op {
        crate::engine::Opcode::Move => "MOVE",
        crate::engine::Opcode::LoadK => "LOADK",
        crate::engine::Opcode::Add => "ADD",
        crate::engine::Opcode::Sub => "SUB",
        crate::engine::Opcode::Mul => "MUL",
        crate::engine::Opcode::Div => "DIV",
        crate::engine::Opcode::Jump => "JUMP",
        crate::engine::Opcode::Return => "RETURN",
        crate::engine::Opcode::Nop => "NOP",
    }
}

fn serialize_bytecode(bytecode: &Bytecode) -> String {
    serde_json::to_string(bytecode).unwrap_or_default()
}

pub fn assemble_loader(payload: &ProtectedPayload) -> String {
    let bc_serialized = serialize_bytecode(&payload.bytecode);
    let watermark = "Protected by Drk V3";
    let encoded_opcodes = encode_opcode_map(&payload.bytecode.opcode_map);
    let guard_checksum = payload.guard.checksum;
    let guard_decoy = payload.guard.decoy_pool;
    let guard_seed = payload.guard.polymorph_seed;
    let guard_packed = payload.guard.packed_len;
    let packed_hex = &payload.bytecode.packed_code_hex;
    format!(
        r#"local json = require('game'):Service('HttpService')
local bit = bit32
local function hex_to_bytes(hex)
    local bytes = {}
    for i = 1, #hex, 2 do
        local byte = tonumber(string.sub(hex, i, i + 1), 16)
        bytes[#bytes + 1] = byte
    end
    return bytes
end
local function unpack_code(hex)
    local bytes = hex_to_bytes(hex)
    local code = {}
    local idx = 1
    local function read_varint()
        local shift, result = 0, 0
        while idx <= #bytes do
            local b = bytes[idx]
            idx = idx + 1
            result = result | ((b & 0x7F) << shift)
            if b & 0x80 == 0 then
                local value = (result >> 1) ~ (-(result & 1))
                return value
            end
            shift = shift + 7
        end
        return nil
    end
    while idx <= #bytes do
        local opcode = bytes[idx]
        idx = idx + 1
        local a = read_varint()
        local b = read_varint()
        local c = read_varint()
        if not (a and b and c) then break end
        code[#code + 1] = { opcode = opcode, a = a, b = b, c = c }
    end
    return code
end
local function anti_tamper()
    local function bail()
        while true do end
    end
    local ok, info = pcall(debug.info, 1, 's')
    if ok and info then
        if tostring(info):find('HttpService') or getfenv then
            bail()
        end
    end
    if debug and debug.sethook then
        local ok_set = pcall(debug.sethook, function() bail() end, "crl")
        if ok_set then
            bail()
        end
    end
    if (getgenv and getgenv().hookfunction) or (hookfunction ~= nil) then
        bail()
    end
end
anti_tamper()
local loader = {}
loader.meta = '{meta}'
loader.enc = '{enc}'
loader.nonce = '{nonce}'
loader.key = '{key}'
loader.watermark = '{watermark}'
loader.opcodes = '{opcodes}'
loader.guard_checksum = {guard_checksum}
loader.guard_decoy = {guard_decoy}
loader.guard_seed = {guard_seed}
loader.guard_packed = {guard_packed}
loader.packed_hex = '{packed_hex}'
local function checksum(payload)
    local acc = 0xA5A55A5AF0F0C3C3
    for i = 1, #payload do
        local b = string.byte(payload, i)
        acc = ((acc + b) % 2^64)
        acc = bit.lrotate(acc, 9) ~ 0xDEADBEEF
    end
    return acc
end
local computed = checksum('{bc}')
if computed ~= loader.guard_checksum then
    while true do end
end
if (#loader.packed_hex / 2) < loader.guard_packed then
    while true do end
end
function loader.run()
    local decoded = json:JSONDecode('{bc}')
    local packed = unpack_code(loader.packed_hex)
    decoded.code = packed
    local aes = require('drk_aes')
    local strings = aes.decrypt(loader.enc, loader.key, loader.nonce)
    local vm = require('vm_core')
    return vm.execute(decoded, strings, loader.opcodes, loader.watermark)
end
return loader
"#,
        meta = general_purpose::STANDARD.encode(watermark.as_bytes()),
        enc = payload.encrypted_strings,
        nonce = payload.nonce,
        key = payload.opaque_key,
        watermark = watermark,
        opcodes = encoded_opcodes,
        guard_checksum = guard_checksum,
        guard_decoy = guard_decoy,
        guard_seed = guard_seed,
        guard_packed = guard_packed,
        packed_hex = packed_hex,
        bc = bc_serialized,
    )
}
