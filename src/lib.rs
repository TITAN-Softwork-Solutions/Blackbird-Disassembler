#![allow(non_snake_case)]

use capstone::prelude::*;
use std::os::raw::c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BkdcInstruction {
    pub address: u64,
    pub size: u8,
    pub _pad: [u8; 7],
    pub mnemonic: [u8; 32],
    pub op_str: [u8; 160],
    /// 0 if not a control-flow instruction
    pub resolved_target: u64,
    /// 0=none 1=direct 2=indirect 3=iat 4=eat
    pub target_kind: u8,
    pub _pad2: [u8; 7],
}

impl Default for BkdcInstruction {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
pub struct BkdcExportEntry {
    pub address: u64,
    pub name: *const u8,
    pub name_len: u32,
    pub _pad: u32,
}

struct ExportMap {
    entries: Vec<(u64, Vec<u8>)>,
}

impl ExportMap {
    fn resolve(&self, addr: u64) -> bool {
        self.entries.iter().any(|(a, _)| *a == addr)
    }
}

fn copy_bytes(dst: &mut [u8], src: &[u8]) {
    let len = src.len().min(dst.len() - 1);
    dst[..len].copy_from_slice(&src[..len]);
    dst[len] = 0;
}

fn is_control_flow(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "jmp" | "je"  | "jne" | "jz"  | "jnz" | "jl"  | "jle" | "jg"  | "jge"
        | "ja" | "jb" | "jae" | "jbe" | "js"   | "jns" | "jo"  | "jno"
        | "jp" | "jnp" | "jcxz" | "jecxz" | "jrcxz" | "call"
    )
}

fn parse_imm_from_op_str(op: &str) -> Option<u64> {
    let s = op.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.len() > 4 {
        u64::from_str_radix(s, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

unsafe fn do_disassemble(
    bytes: *const u8,
    byte_len: u32,
    base_address: u64,
    out: *mut BkdcInstruction,
    out_capacity: u32,
    export_map: Option<&ExportMap>,
) -> u32 {
    if bytes.is_null() || out.is_null() || byte_len == 0 || out_capacity == 0 {
        return 0;
    }

    let cs = match Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .detail(true)
        .build()
    {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let data = std::slice::from_raw_parts(bytes, byte_len as usize);
    let insns = match cs.disasm_all(data, base_address) {
        Ok(i) => i,
        Err(_) => return 0,
    };

    let mut count = 0u32;
    for insn in insns.iter() {
        if count >= out_capacity {
            break;
        }

        let mut entry = BkdcInstruction::default();
        entry.address = insn.address();
        entry.size = insn.bytes().len() as u8;

        let mn  = insn.mnemonic().unwrap_or("");
        let ops = insn.op_str().unwrap_or("");

        copy_bytes(&mut entry.mnemonic, mn.as_bytes());
        copy_bytes(&mut entry.op_str, ops.as_bytes());

        if is_control_flow(mn) {
            let is_indirect = ops.contains('[');
            if is_indirect {
                entry.target_kind = 2;
            } else if let Some(target) = parse_imm_from_op_str(ops) {
                let kind = if let Some(em) = export_map {
                    if em.resolve(target) { 3 } else { 1 }
                } else {
                    1
                };
                entry.resolved_target = target;
                entry.target_kind = kind;
            } else {
                entry.target_kind = 2;
            }
        }

        out.add(count as usize).write(entry);
        count += 1;
    }

    count
}

/// Disassemble `byte_len` bytes of x64 code at `base_address`.
/// Writes at most `out_capacity` entries into `out`.
/// Returns the number of instructions written.
#[no_mangle]
pub unsafe extern "C" fn BkDsDisassemble(
    bytes: *const u8,
    byte_len: u32,
    base_address: u64,
    out: *mut BkdcInstruction,
    out_capacity: u32,
) -> u32 {
    do_disassemble(bytes, byte_len, base_address, out, out_capacity, None)
}

/// Disassemble with optional IAT/EAT resolution.
/// `context` must be a pointer from `BkDcSetExportMap`, or null.
#[no_mangle]
pub unsafe extern "C" fn BkDsDisassembleEx(
    bytes: *const u8,
    byte_len: u32,
    base_address: u64,
    out: *mut BkdcInstruction,
    out_capacity: u32,
    context: *mut c_void,
) -> u32 {
    let em = if context.is_null() {
        None
    } else {
        Some(&*(context as *const ExportMap))
    };
    do_disassemble(bytes, byte_len, base_address, out, out_capacity, em)
}

/// Build an export map for IAT/EAT resolution.
/// On success writes a heap-allocated context pointer to `*context` and returns true.
/// The caller must free it with `BkDcFreeContext`.
#[no_mangle]
pub unsafe extern "C" fn BkDcSetExportMap(
    entries: *const BkdcExportEntry,
    count: u32,
    context: *mut *mut c_void,
) -> bool {
    if context.is_null() {
        return false;
    }
    *context = std::ptr::null_mut();

    if entries.is_null() || count == 0 {
        return false;
    }

    let mut map = ExportMap { entries: Vec::with_capacity(count as usize) };
    for i in 0..count as usize {
        let e = &*entries.add(i);
        let name = if e.name.is_null() || e.name_len == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(e.name, e.name_len as usize).to_vec()
        };
        map.entries.push((e.address, name));
    }

    *context = Box::into_raw(Box::new(map)) as *mut c_void;
    true
}

/// Free a context created by `BkDcSetExportMap`.
#[no_mangle]
pub unsafe extern "C" fn BkDcFreeContext(context: *mut c_void) {
    if !context.is_null() {
        drop(Box::from_raw(context as *mut ExportMap));
    }
}
