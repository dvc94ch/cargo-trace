use anyhow::Result;
pub use bpf_probes::*;
use libbpf_rs::{Map, MapFlags, Object, ObjectBuilder, OpenObject};
use std::marker::PhantomData;
use zerocopy::{AsBytes, FromBytes, LayoutVerified, Unaligned};

pub type I16 = zerocopy::byteorder::I16<byteorder::NativeEndian>;
pub type I32 = zerocopy::byteorder::I32<byteorder::NativeEndian>;
pub type I64 = zerocopy::byteorder::I64<byteorder::NativeEndian>;
pub type U16 = zerocopy::byteorder::U16<byteorder::NativeEndian>;
pub type U32 = zerocopy::byteorder::U32<byteorder::NativeEndian>;
pub type U64 = zerocopy::byteorder::U64<byteorder::NativeEndian>;

pub mod utils {
    pub use bpf_utils::dylibs::{BinaryInfo, Pid};
    pub use bpf_utils::ehframe;
    pub use bpf_utils::elf::{Dwarf, Elf};
    pub use bpf_utils::kallsyms::{KernelSymbol, KernelSymbolTable};
    pub use bpf_utils::maps::{AddressEntry, AddressMap};
    pub use bpf_utils::syscall::syscall_table;
    pub use sudo;
}

pub struct BpfBuilder {
    child_pid: Option<u32>,
    probes: Vec<(Probe, &'static str)>,
    new_obj: OpenObject,
}

impl BpfBuilder {
    pub fn new(prog: &[u8]) -> Result<Self> {
        bpf_utils::rlimit::increase_memlock_rlimit()?;
        let new_obj = ObjectBuilder::default()
            .relaxed_maps(true)
            .open_memory("bpf", prog)?;
        Ok(Self {
            child_pid: None,
            probes: Default::default(),
            new_obj,
        })
    }

    pub fn set_child_pid<T: Into<u32>>(mut self, pid: T) -> Self {
        self.child_pid = Some(pid.into());
        self
    }

    pub fn attach_probe_str(self, probe: &str, entry: &'static str) -> Result<Self> {
        self.attach_probe(probe.parse()?, entry)
    }

    pub fn attach_probe(mut self, probe: Probe, entry: &'static str) -> Result<Self> {
        let new_prog = self.new_obj.prog(entry)?.unwrap();
        new_prog.set_prog_type(probe.prog_type());
        if let Some(attach_type) = probe.attach_type() {
            new_prog.set_attach_type(attach_type);
        }
        self.probes.push((probe, entry));
        Ok(self)
    }

    pub fn load(self) -> Result<Bpf> {
        let mut obj = self.new_obj.load()?;
        let mut probes = vec![];
        for (probe, entry) in self.probes {
            let prog = obj.prog(entry)?.unwrap();
            probes.extend(probe.attach(prog, self.child_pid)?);
        }
        Ok(Bpf {
            obj,
            _probes: probes,
        })
    }
}

pub struct Bpf {
    obj: Object,
    _probes: Vec<AttachedProbe>,
}

impl Bpf {
    pub fn hash_map<K, V>(&mut self, map: &str) -> Result<BpfHashMap<'_, K, V>>
    where
        K: AsBytes + FromBytes + Unaligned + Clone,
        V: AsBytes + FromBytes + Unaligned + Clone,
    {
        Ok(BpfHashMap::new(self.obj.map(map)?.unwrap()))
    }

    pub fn array<V>(&mut self, map: &str) -> Result<BpfHashMap<'_, U32, V>>
    where
        V: AsBytes + FromBytes + Unaligned + Clone,
    {
        Ok(BpfHashMap::new(self.obj.map(map)?.unwrap()))
    }

    pub fn stack_trace(&mut self, map: &str) -> Result<BpfStackTrace<'_>> {
        Ok(BpfStackTrace::new(self.obj.map(map)?.unwrap()))
    }
}

pub struct BpfHashMap<'a, K, V> {
    map: &'a mut Map,
    _marker: PhantomData<(K, V)>,
}

impl<'a, K, V> BpfHashMap<'a, K, V>
where
    K: AsBytes + FromBytes + Unaligned + Clone,
    V: AsBytes + FromBytes + Unaligned + Clone,
{
    pub fn new(map: &'a mut Map) -> Self {
        Self {
            map,
            _marker: PhantomData,
        }
    }

    pub fn get(&self, key: &K) -> Result<Option<V>> {
        if let Some(bytes) = self.map.lookup(key.as_bytes(), MapFlags::empty())? {
            if let Some(layout) = LayoutVerified::<_, V>::new_unaligned(bytes.as_slice()) {
                return Ok(Some(layout.into_ref().clone()));
            }
        }
        Ok(None)
    }

    pub fn insert(&mut self, key: &K, value: &V) -> Result<()> {
        self.map
            .update(key.as_bytes(), value.as_bytes(), MapFlags::empty())?;
        Ok(())
    }

    pub fn keys(&self) -> impl Iterator<Item = K> + '_ {
        self.map.keys().filter_map(|bytes| {
            LayoutVerified::<_, K>::new_unaligned(bytes.as_slice())
                .map(|layout| layout.into_ref().clone())
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = (K, V)> + '_ {
        self.keys().filter_map(move |key| {
            self.get(&key)
                .ok()
                .unwrap_or_default()
                .map(move |value| (key, value))
        })
    }
}

const BPF_MAX_STACK_DEPTH: usize = 127;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(C)]
pub struct BpfStackFrames {
    pub ip: [u64; BPF_MAX_STACK_DEPTH],
}

impl BpfStackFrames {
    pub fn iter(&self) -> impl Iterator<Item = u64> + '_ {
        self.ip.iter().take_while(|ip| **ip != 0).copied()
    }
}

pub struct BpfStackTrace<'a> {
    map: &'a mut Map,
}

impl<'a> BpfStackTrace<'a> {
    pub fn new(map: &'a mut Map) -> Self {
        Self { map }
    }

    pub fn raw_stack_trace(&self, id: u32) -> Result<Option<BpfStackFrames>> {
        if let Some(bytes) = self.map.lookup(&id.to_ne_bytes()[..], MapFlags::empty())? {
            let frames = unsafe { *(bytes.as_slice().as_ptr() as *const BpfStackFrames) };
            Ok(Some(frames))
        } else {
            Ok(None)
        }
    }
}
