//! Coordination wire messages, gossiped into the cluster's SVS group. This is
//! ndn-rs's own coordination protocol (not a cross-impl wire standard), so the
//! TLV namespace is private (`0x1E00…`). Each message is one publication.

use bytes::Bytes;
use ndn_packet::Name;
use ndn_tlv::{TlvReader, TlvWriter};

mod t {
    // Message variants.
    pub const HEARTBEAT: u64 = 0x1E00;
    pub const JOB: u64 = 0x1E01;
    pub const CLAIM: u64 = 0x1E02;
    pub const RELEASE: u64 = 0x1E03;
    // Fields.
    pub const NODE: u64 = 0x1E10; // NameContainer
    pub const TARGET: u64 = 0x1E11; // NameContainer
    pub const JOB_REF: u64 = 0x1E12; // NameContainer
    pub const CAP_USED: u64 = 0x1E14;
    pub const CAP_TOTAL: u64 = 0x1E15;
    pub const EPOCH: u64 = 0x1E16;
    pub const REPL: u64 = 0x1E17;
    pub const TS: u64 = 0x1E18;
}

/// A coordination message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClusterMsg {
    /// Liveness + capacity report from `node`.
    Heartbeat {
        node: Name,
        capacity_used: u64,
        capacity_total: u64,
        epoch: u64,
    },
    /// Announce a unit of durable work (replicate `target`).
    Job {
        target: Name,
        /// 0 = use the cluster default.
        replication_factor: u64,
    },
    /// `node` claims responsibility for `job` at `ts`.
    Claim { job: Name, node: Name, ts: u64 },
    /// `node` relinquishes `job`.
    Release { job: Name, node: Name },
}

impl ClusterMsg {
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        match self {
            ClusterMsg::Heartbeat { node, capacity_used, capacity_total, epoch } => {
                w.write_nested(t::HEARTBEAT, |w| {
                    name_container(w, t::NODE, node);
                    nni(w, t::CAP_USED, *capacity_used);
                    nni(w, t::CAP_TOTAL, *capacity_total);
                    nni(w, t::EPOCH, *epoch);
                });
            }
            ClusterMsg::Job { target, replication_factor } => {
                w.write_nested(t::JOB, |w| {
                    name_container(w, t::TARGET, target);
                    nni(w, t::REPL, *replication_factor);
                });
            }
            ClusterMsg::Claim { job, node, ts } => {
                w.write_nested(t::CLAIM, |w| {
                    name_container(w, t::JOB_REF, job);
                    name_container(w, t::NODE, node);
                    nni(w, t::TS, *ts);
                });
            }
            ClusterMsg::Release { job, node } => {
                w.write_nested(t::RELEASE, |w| {
                    name_container(w, t::JOB_REF, job);
                    name_container(w, t::NODE, node);
                });
            }
        }
        w.finish()
    }

    /// Parse a coordination message; `None` for anything else (so non-cluster
    /// publications in the group are ignored).
    pub fn decode(value: Bytes) -> Option<ClusterMsg> {
        let mut r = TlvReader::new(value);
        let (typ, val) = r.read_tlv().ok()?;
        match typ {
            t::HEARTBEAT => {
                let f = Fields::parse(val);
                Some(ClusterMsg::Heartbeat {
                    node: f.node?,
                    capacity_used: f.cap_used,
                    capacity_total: f.cap_total,
                    epoch: f.epoch,
                })
            }
            t::JOB => {
                let f = Fields::parse(val);
                Some(ClusterMsg::Job {
                    target: f.target?,
                    replication_factor: f.repl,
                })
            }
            t::CLAIM => {
                let f = Fields::parse(val);
                Some(ClusterMsg::Claim {
                    job: f.job?,
                    node: f.node?,
                    ts: f.ts,
                })
            }
            t::RELEASE => {
                let f = Fields::parse(val);
                Some(ClusterMsg::Release { job: f.job?, node: f.node? })
            }
            _ => None,
        }
    }
}

#[derive(Default)]
struct Fields {
    node: Option<Name>,
    target: Option<Name>,
    job: Option<Name>,
    cap_used: u64,
    cap_total: u64,
    epoch: u64,
    repl: u64,
    ts: u64,
}

impl Fields {
    fn parse(value: Bytes) -> Self {
        let mut f = Fields::default();
        let mut r = TlvReader::new(value);
        while let Ok((typ, val)) = r.read_tlv() {
            match typ {
                t::NODE => f.node = decode_name_container(val),
                t::TARGET => f.target = decode_name_container(val),
                t::JOB_REF => f.job = decode_name_container(val),
                t::CAP_USED => f.cap_used = decode_nni(&val),
                t::CAP_TOTAL => f.cap_total = decode_nni(&val),
                t::EPOCH => f.epoch = decode_nni(&val),
                t::REPL => f.repl = decode_nni(&val),
                t::TS => f.ts = decode_nni(&val),
                _ => {}
            }
            if r.is_empty() {
                break;
            }
        }
        f
    }
}

fn name_container(w: &mut TlvWriter, typ: u64, name: &Name) {
    w.write_nested(typ, |w| w.write_raw(&name.encode_to_tlv()));
}

fn decode_name_container(value: Bytes) -> Option<Name> {
    Name::decode_from_tlv(value).ok()
}

fn nni(w: &mut TlvWriter, typ: u64, value: u64) {
    let bytes: Vec<u8> = if value <= u8::MAX as u64 {
        vec![value as u8]
    } else if value <= u16::MAX as u64 {
        (value as u16).to_be_bytes().to_vec()
    } else if value <= u32::MAX as u64 {
        (value as u32).to_be_bytes().to_vec()
    } else {
        value.to_be_bytes().to_vec()
    };
    w.write_tlv(typ, &bytes);
}

fn decode_nni(bytes: &[u8]) -> u64 {
    let mut v = 0u64;
    for &b in bytes {
        v = (v << 8) | b as u64;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn heartbeat_roundtrips() {
        let m = ClusterMsg::Heartbeat {
            node: n("/cluster/r/a"),
            capacity_used: 1234,
            capacity_total: 100_000,
            epoch: 7,
        };
        assert_eq!(ClusterMsg::decode(m.encode()).unwrap(), m);
    }

    #[test]
    fn job_claim_release_roundtrip() {
        for m in [
            ClusterMsg::Job { target: n("/obj/big"), replication_factor: 3 },
            ClusterMsg::Claim { job: n("/obj/big"), node: n("/r/a"), ts: 99 },
            ClusterMsg::Release { job: n("/obj/big"), node: n("/r/a") },
        ] {
            assert_eq!(ClusterMsg::decode(m.encode()).unwrap(), m);
        }
    }

    #[test]
    fn non_cluster_bytes_decode_to_none() {
        assert!(ClusterMsg::decode(Bytes::from_static(&[0x07, 0x02, 0x08, 0x00])).is_none());
    }
}
