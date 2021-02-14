use anyhow::Result;
use byteorder::BigEndian;
use std::path::Path;
use zerocopy::{AsBytes, FromBytes, Unaligned, U16, U32, U64};

pub const MAGIC_NUMBER: u64 = 0xd7_4c_90_35_f0_61_ef_7f;
pub const X86_64_REGS: &[u8] = &[
    libc::REG_RIP as u8,
    libc::REG_RSP as u8,
    libc::REG_RBP as u8,
    libc::REG_RBX as u8,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct Header {
    magic: U64<BigEndian>,
    len: U64<BigEndian>,
    width: u8,
    regs: [u8; 24],
}

#[allow(clippy::len_without_is_empty)]
impl Header {
    pub fn new(len: usize, registers: &[u8]) -> Self {
        let mut regs = [0; 24];
        regs[..registers.len()].copy_from_slice(registers);
        Self {
            magic: U64::new(MAGIC_NUMBER),
            len: U64::new(len as _),
            width: regs.len() as _,
            regs,
        }
    }

    pub fn magic(&self) -> u64 {
        self.magic.get()
    }

    pub fn len(&self) -> usize {
        self.len.get() as _
    }

    pub fn width(&self) -> usize {
        self.width as _
    }

    pub fn row_size(&self) -> usize {
        self.len() * 8
    }

    pub fn register(&self, reg: u8) -> Option<usize> {
        self.regs[..self.width()]
            .iter()
            .enumerate()
            .find(|(_, reg2)| **reg2 == reg)
            .map(|(i, _)| i)
    }

    pub fn size(&self) -> usize {
        std::mem::size_of::<Self>() + (self.width() + 1) * self.row_size()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct Instruction {
    op: u8,
    reg: u8,
    offset1: U16<BigEndian>,
    offset2: U32<BigEndian>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Op {
    /// This type of register is not supported.
    Unimplemented = 0,
    /// Undefined register. The value will be defined at some
    /// later IP in the same DIE.
    Undefined = 1,
    /// Value stored at some offset from `CFA`.
    CfaOffset = 2,
    /// Value of a machine register plus offset.
    Register = 3,
    /// Value is the evaluation of the standard PLT
    /// expression, ie `((rip & 15) >= 11) >> 3 + rsp`.
    /// This is hardcoded because it is a common expression.
    PltExpr = 4,
}

impl Instruction {
    pub fn new(op: Op, reg: u8, offset: isize) -> Self {
        let uoffset = -(offset + 1) as u64;
        let offset2 = (uoffset & 0xffff_ffff) as u32;
        let offset1 = (uoffset - offset2 as u64) as u16;
        assert_eq!(-1 - (offset1 as isize + offset2 as isize), offset);
        Self {
            op: op as _,
            reg,
            offset1: U16::new(offset1 as u16),
            offset2: U32::new(offset2 as u32),
        }
    }

    pub fn op(&self) -> Op {
        match self.op {
            op if op == Op::Unimplemented as u8 => Op::Unimplemented,
            op if op == Op::Undefined as u8 => Op::Undefined,
            op if op == Op::CfaOffset as u8 => Op::CfaOffset,
            op if op == Op::Register as u8 => Op::Register,
            op if op == Op::PltExpr as u8 => Op::PltExpr,
            _ => Op::Unimplemented,
        }
    }

    pub fn reg(&self) -> u8 {
        self.reg
    }

    pub fn offset(&self) -> isize {
        -1 - (self.offset1.get() as isize + self.offset2.get() as isize)
    }
}

pub struct File<'a> {
    _file: std::fs::File,
    _mmap: memmap::MmapMut,
    header: Header,
    addresses: &'a mut [U64<BigEndian>],
    instructions: Vec<&'a mut [Instruction]>,
}

impl<'a> File<'a> {
    pub fn open<T: AsRef<Path>>(path: T) -> Result<Self> {
        let file = std::fs::File::open(path)?;
        let mut mmap = unsafe { memmap::Mmap::map(&file) }?.make_mut()?;
        let len = mmap.len();
        if len < std::mem::size_of::<Header>() {
            return Err(anyhow::anyhow!("size smaller than header"));
        }
        let (header, data) = mmap.split_at_mut(std::mem::size_of::<Header>());
        let header = unsafe { *(header as *const _ as *const Header) };
        if header.magic() != MAGIC_NUMBER {
            return Err(anyhow::anyhow!("magic number doesn't match"));
        }
        if len != header.size() {
            return Err(anyhow::anyhow!("file size doesn't match header"));
        }
        let (addrs, mut regs) = data.split_at_mut(header.row_size());
        let addresses = unsafe { &mut *(addrs as *mut _ as *mut _) };
        let mut instructions = Vec::with_capacity(header.width());
        for _ in 0..header.width() {
            let (insts, nregs) = regs.split_at_mut(header.row_size());
            regs = nregs;
            instructions.push(unsafe { &mut *(insts as *mut _ as *mut _) });
        }
        Ok(Self {
            _file: file,
            _mmap: mmap,
            header,
            addresses,
            instructions,
        })
    }

    pub fn create<T: AsRef<Path>>(path: T, header: Header) -> Result<Self> {
        let file = std::fs::File::create(path)?;
        file.set_len(header.size() as u64)?;
        let mut mmap = unsafe { memmap::Mmap::map(&file) }?.make_mut()?;
        let (hdr, data) = mmap.split_at_mut(std::mem::size_of::<Header>());
        hdr.copy_from_slice(header.as_bytes());
        let (addrs, mut regs) = data.split_at_mut(header.row_size());
        let addresses = unsafe { &mut *(addrs as *mut _ as *mut _) };
        let mut instructions = Vec::with_capacity(header.width());
        for _ in 0..header.width() {
            let (insts, nregs) = regs.split_at_mut(header.row_size());
            regs = nregs;
            instructions.push(unsafe { &mut *(insts as *mut _ as *mut _) });
        }
        Ok(Self {
            _file: file,
            _mmap: mmap,
            header,
            addresses,
            instructions,
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn addresses(&self) -> &[U64<BigEndian>] {
        self.addresses
    }

    pub fn addresses_mut(&mut self) -> &mut [U64<BigEndian>] {
        self.addresses
    }

    pub fn instructions(&self, register: u8) -> Option<&[Instruction]> {
        let i = self.header.register(register)?;
        Some(self.instructions[i])
    }

    pub fn instructions_mut(&mut self, register: u8) -> Option<&mut [Instruction]> {
        let i = self.header.register(register)?;
        Some(self.instructions[i])
    }
}
