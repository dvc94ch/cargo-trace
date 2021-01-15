use anyhow::Result;
use bpf_probes::Probe;
use libbpf_rs::{Object, ObjectBuilder, OpenObject};

pub struct BpfBuilder {
    probes: Vec<(Probe, &'static str)>,
    new_obj: OpenObject,
}

impl BpfBuilder {
    pub fn new(prog: &[u8]) -> Result<Self> {
        sudo::escalate_if_needed().unwrap();
        bpf_utils::rlimit::increase_memlock_rlimit()?;
        let new_obj = ObjectBuilder::default().open_memory("bpf", prog)?;
        Ok(Self {
            probes: Default::default(),
            new_obj,
        })
    }

    pub fn attach_probe(mut self, probe: &str, entry: &'static str) -> Result<Self> {
        let probe: Probe = probe.parse()?;
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
        for (probe, entry) in self.probes {
            let prog = obj.prog(entry)?.unwrap();
            probe.attach(prog)?;
        }
        Ok(Bpf(obj))
    }
}

pub struct Bpf(Object);
