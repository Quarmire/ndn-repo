//! `RepoCmd` wire codec — byte-compatible with ndnd's repo command protocol
//! (`github.com/named-data/ndnd/repo/tlv/definitions.go`). The TLV type codes
//! and structure are reproduced exactly so an ndnd `repo-ng`/`ndnd repo`
//! client can command an `ndn-repo` and vice versa.
//!
//! A command is carried in the `ApplicationParameters` of an Interest to the
//! repo's command prefix; the reply is a `RepoCmdRes`. `BlobFetch` may also be
//! *published into the SVS group* (in-band insertion), exactly as ndnd does.

use bytes::Bytes;
use ndn_packet::{Name, NameComponent};
use ndn_tlv::{TlvReader, TlvWriter};

/// TLV type codes (ndnd `repo/tlv/definitions.go`). Kept public so conformance
/// tests can assert them against the reference.
pub mod tlv_type {
    pub const SYNC_JOIN: u64 = 0x1DB0;
    pub const SYNC_LEAVE: u64 = 0x1DB1;
    pub const BLOB_FETCH: u64 = 0x1DB2;
    pub const SECURITY_CONFIG: u64 = 0x1DB4;

    pub const PROTOCOL: u64 = 0x191;
    pub const GROUP: u64 = 0x193;
    pub const MULTICAST_PREFIX: u64 = 0x194;
    pub const HISTORY_SNAPSHOT: u64 = 0x1A4;
    pub const HISTORY_THRESHOLD: u64 = 0x1A5;
    pub const BLOB_NAME: u64 = 0x1B8;
    pub const BLOB_DATA: u64 = 0x1BA;

    pub const RES_STATUS: u64 = 0x291;
    pub const RES_MESSAGE: u64 = 0x292;

    /// The NDN `Name` TLV nested inside a `NameContainer`.
    pub const NAME: u64 = 0x07;
}

/// The SVS-v3 sync protocol name (`/ndn/svs/v=3`) — ndnd `SyncProtocolSvsV3`.
/// A `SyncJoin.protocol` equal to this selects SVS-v3 ingestion.
pub fn sync_protocol_svs_v3() -> Name {
    Name::from_components([
        NameComponent::keyword(Bytes::from_static(b"ndn")),
        NameComponent::keyword(Bytes::from_static(b"svs")),
    ])
    .append_version(3)
}

/// A parsed repo command (exactly one variant present on the wire).
// Constructed once per command at the parse boundary (never hot), so the
// size spread between SyncJoin and the smaller variants is irrelevant.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoCmd {
    SyncJoin(SyncJoin),
    SyncLeave(SyncLeave),
    BlobFetch(BlobFetch),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncJoin {
    /// Sync protocol name; `Some(sync_protocol_svs_v3())` for SVS-v3.
    pub protocol: Option<Name>,
    /// The SVS group prefix to join and durably ingest.
    pub group: Option<Name>,
    pub multicast_prefix: Option<Name>,
    /// History-snapshot threshold (ndnd requires `>= 10` when present).
    pub history_threshold: Option<u64>,
    /// Name of a `SecurityConfigObject` (LVS schema + anchors) to fetch.
    pub security_config: Option<Name>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SyncLeave {
    pub protocol: Option<Name>,
    pub group: Option<Name>,
}

/// Fetch a named blob into the repo, or directly carry Data wires to store.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BlobFetch {
    /// Name to fetch and store.
    pub name: Option<Name>,
    /// Inline Data packet wires to store directly (push insertion).
    pub data: Vec<Bytes>,
}

/// Command response (`RepoCmdRes`): NFD-style numeric status + message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoCmdRes {
    pub status: u64,
    pub message: String,
}

impl RepoCmdRes {
    pub fn ok() -> Self {
        Self { status: 200, message: String::new() }
    }

    pub fn err(status: u64, message: impl Into<String>) -> Self {
        Self { status, message: message.into() }
    }

    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        write_nni(&mut w, tlv_type::RES_STATUS, self.status);
        if !self.message.is_empty() {
            w.write_tlv(tlv_type::RES_MESSAGE, self.message.as_bytes());
        }
        w.finish()
    }

    pub fn decode(value: Bytes) -> Option<Self> {
        let mut r = TlvReader::new(value);
        let mut status = 0u64;
        let mut message = String::new();
        while !r.is_empty() {
            let (typ, val) = r.read_tlv().ok()?;
            match typ {
                tlv_type::RES_STATUS => status = decode_nni(&val),
                tlv_type::RES_MESSAGE => {
                    message = String::from_utf8(val.to_vec()).ok()?;
                }
                _ => {}
            }
        }
        Some(Self { status, message })
    }
}

impl RepoCmd {
    /// Encode this command as the `ApplicationParameters` value (one top-level
    /// variant TLV), matching ndnd's `RepoCmd` field layout.
    pub fn encode(&self) -> Bytes {
        let mut w = TlvWriter::new();
        match self {
            RepoCmd::SyncJoin(j) => w.write_nested(tlv_type::SYNC_JOIN, |w| {
                name_container_opt(w, tlv_type::PROTOCOL, &j.protocol);
                name_container_opt(w, tlv_type::GROUP, &j.group);
                name_container_opt(w, tlv_type::MULTICAST_PREFIX, &j.multicast_prefix);
                if let Some(t) = j.history_threshold {
                    w.write_nested(tlv_type::HISTORY_SNAPSHOT, |w| {
                        write_nni(w, tlv_type::HISTORY_THRESHOLD, t);
                    });
                }
                name_container_opt(w, tlv_type::SECURITY_CONFIG, &j.security_config);
            }),
            RepoCmd::SyncLeave(l) => w.write_nested(tlv_type::SYNC_LEAVE, |w| {
                name_container_opt(w, tlv_type::PROTOCOL, &l.protocol);
                name_container_opt(w, tlv_type::GROUP, &l.group);
            }),
            RepoCmd::BlobFetch(b) => w.write_nested(tlv_type::BLOB_FETCH, |w| {
                name_container_opt(w, tlv_type::BLOB_NAME, &b.name);
                for d in &b.data {
                    w.write_tlv(tlv_type::BLOB_DATA, d);
                }
            }),
        }
        w.finish()
    }

    /// Parse a command from an `ApplicationParameters` value. Returns `None`
    /// if the bytes are not a recognised repo command (so application data
    /// published in a group is ignored, as in ndnd `processIncomingPub`).
    pub fn decode(value: Bytes) -> Option<RepoCmd> {
        let mut r = TlvReader::new(value);
        let (typ, val) = r.read_tlv().ok()?;
        match typ {
            tlv_type::SYNC_JOIN => Some(RepoCmd::SyncJoin(decode_sync_join(val)?)),
            tlv_type::SYNC_LEAVE => Some(RepoCmd::SyncLeave(decode_sync_leave(val)?)),
            tlv_type::BLOB_FETCH => Some(RepoCmd::BlobFetch(decode_blob_fetch(val)?)),
            _ => None,
        }
    }
}

fn decode_sync_join(value: Bytes) -> Option<SyncJoin> {
    let mut j = SyncJoin::default();
    let mut r = TlvReader::new(value);
    while !r.is_empty() {
        let (typ, val) = r.read_tlv().ok()?;
        match typ {
            tlv_type::PROTOCOL => j.protocol = decode_name_container(val),
            tlv_type::GROUP => j.group = decode_name_container(val),
            tlv_type::MULTICAST_PREFIX => j.multicast_prefix = decode_name_container(val),
            tlv_type::HISTORY_SNAPSHOT => {
                let mut hr = TlvReader::new(val);
                while !hr.is_empty() {
                    let (t, v) = hr.read_tlv().ok()?;
                    if t == tlv_type::HISTORY_THRESHOLD {
                        j.history_threshold = Some(decode_nni(&v));
                    }
                }
            }
            tlv_type::SECURITY_CONFIG => j.security_config = decode_name_container(val),
            _ => {}
        }
    }
    Some(j)
}

fn decode_sync_leave(value: Bytes) -> Option<SyncLeave> {
    let mut l = SyncLeave::default();
    let mut r = TlvReader::new(value);
    while !r.is_empty() {
        let (typ, val) = r.read_tlv().ok()?;
        match typ {
            tlv_type::PROTOCOL => l.protocol = decode_name_container(val),
            tlv_type::GROUP => l.group = decode_name_container(val),
            _ => {}
        }
    }
    Some(l)
}

fn decode_blob_fetch(value: Bytes) -> Option<BlobFetch> {
    let mut b = BlobFetch::default();
    let mut r = TlvReader::new(value);
    while !r.is_empty() {
        let (typ, val) = r.read_tlv().ok()?;
        match typ {
            tlv_type::BLOB_NAME => b.name = decode_name_container(val),
            tlv_type::BLOB_DATA => b.data.push(val),
            _ => {}
        }
    }
    Some(b)
}

/// Encode a `NameContainer` (`<typ> { <Name 0x07> }`) when the name is present.
fn name_container_opt(w: &mut TlvWriter, typ: u64, name: &Option<Name>) {
    if let Some(name) = name {
        w.write_nested(typ, |w| w.write_raw(&name.encode_to_tlv()));
    }
}

/// Decode a `NameContainer`: the value is a nested `Name` (0x07) TLV.
fn decode_name_container(value: Bytes) -> Option<Name> {
    Name::decode_from_tlv(value).ok()
}

fn write_nni(w: &mut TlvWriter, typ: u64, value: u64) {
    // NDN NonNegativeInteger: minimal 1/2/4/8-byte big-endian width.
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

    /// The TLV type codes must match ndnd `repo/tlv/definitions.go` exactly —
    /// the wire-compatibility contract.
    #[test]
    fn tlv_codes_match_ndnd() {
        assert_eq!(tlv_type::SYNC_JOIN, 0x1DB0);
        assert_eq!(tlv_type::SYNC_LEAVE, 0x1DB1);
        assert_eq!(tlv_type::BLOB_FETCH, 0x1DB2);
        assert_eq!(tlv_type::SECURITY_CONFIG, 0x1DB4);
        assert_eq!(tlv_type::PROTOCOL, 0x191);
        assert_eq!(tlv_type::GROUP, 0x193);
        assert_eq!(tlv_type::RES_STATUS, 0x291);
    }

    #[test]
    fn sync_protocol_is_ndn_svs_v3() {
        // /ndn/svs/v=3 — keyword "ndn", keyword "svs", version 3.
        let p = sync_protocol_svs_v3();
        let comps = p.components();
        assert_eq!(comps.len(), 3);
        assert_eq!(comps[0].value.as_ref(), b"ndn");
        assert_eq!(comps[1].value.as_ref(), b"svs");
        assert_eq!(comps[2].as_segment().is_none(), true);
    }

    #[test]
    fn sync_join_roundtrips() {
        let cmd = RepoCmd::SyncJoin(SyncJoin {
            protocol: Some(sync_protocol_svs_v3()),
            group: Some("/my/group".parse().unwrap()),
            multicast_prefix: None,
            history_threshold: Some(50),
            security_config: Some("/my/seccfg/v=1".parse().unwrap()),
        });
        let wire = cmd.encode();
        // Top-level TLV must be SYNC_JOIN (0x1DB0 → 3-byte varnumber FD 1D B0).
        assert_eq!(wire[0..3], [0xFD, 0x1D, 0xB0]);
        let decoded = RepoCmd::decode(wire).expect("decode");
        assert_eq!(decoded, cmd);
    }

    #[test]
    fn sync_leave_roundtrips() {
        let cmd = RepoCmd::SyncLeave(SyncLeave {
            protocol: Some(sync_protocol_svs_v3()),
            group: Some("/my/group".parse().unwrap()),
        });
        assert_eq!(RepoCmd::decode(cmd.encode()).unwrap(), cmd);
    }

    #[test]
    fn blob_fetch_with_inline_data_roundtrips() {
        use ndn_packet::encode::DataBuilder;
        let d1 = DataBuilder::new("/g/obj/v=1/seg=0".parse::<Name>().unwrap(), b"hello").build();
        let cmd = RepoCmd::BlobFetch(BlobFetch {
            name: Some("/g/obj".parse().unwrap()),
            data: vec![d1.clone()],
        });
        let decoded = RepoCmd::decode(cmd.encode()).unwrap();
        assert_eq!(decoded, cmd);
        if let RepoCmd::BlobFetch(b) = decoded {
            assert_eq!(b.data[0], d1);
        }
    }

    #[test]
    fn response_roundtrips() {
        let res = RepoCmdRes::err(500, "boom");
        let decoded = RepoCmdRes::decode(res.encode()).unwrap();
        assert_eq!(decoded, res);
        assert_eq!(RepoCmdRes::decode(RepoCmdRes::ok().encode()).unwrap().status, 200);
    }

    #[test]
    fn non_command_bytes_decode_to_none() {
        // Application data published in a group is not a repo command.
        assert!(RepoCmd::decode(Bytes::from_static(&[0x07, 0x03, 0x08, 0x01, b'x'])).is_none());
    }
}
