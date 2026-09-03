//! SRVSVC (MS-SRVS) — `NetrSessionEnum` over the `\srvsvc` named pipe.
//!
//! Enumerates the logon sessions a host sees: for each, the client computer and the user. This
//! is the session-hunting primitive — it locates where privileged
//! users are logged on so the attacker knows which host to compromise to steal their credentials.
//!
//! Rides the same SMB DCE/RPC transport as SAMR/LSAT. Level 10 (`SESSION_INFO_10`) is the least
//! privileged view (client + user name), readable by any authenticated user on many hosts.

use crate::ndr::{NdrDecoder, NdrEncoder};
use crate::transport::SmbPipe;
use crate::{Result, RpcError, Syntax};
use smb2_client::SmbClient;

/// The SRVSVC interface, v3.0.
pub fn srvsvc_syntax() -> Syntax {
    Syntax::new("4b324fc8-1670-01d3-1278-5a47bf6ee188", 3, 0)
}

pub mod opnum {
    pub const NETR_SESSION_ENUM: u16 = 12;
    pub const NETR_SHARE_ENUM: u16 = 15;
}

const SESSION_LEVEL_10: u32 = 10;
const SHARE_LEVEL_1: u32 = 1;

/// One logon session as reported by `NetrSessionEnum` level 10.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    /// The client computer name the session originates from (`sesi10_cname`).
    pub client: String,
    /// The user account logged on (`sesi10_username`).
    pub user: String,
}

/// Marshal a `NetrSessionEnum(ServerName=NULL, ClientName=NULL, UserName=NULL, Level=10)` request.
/// `ServerName` NULL lets the server infer itself (per MS-SRVS `NetrSessionEnum` IDL).
pub fn encode_session_enum() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.null_ptr(); // ServerName  [in,string,unique] = NULL
    e.null_ptr(); // ClientName  [in,string,unique] = NULL
    e.null_ptr(); // UserName    [in,string,unique] = NULL

    // SESSION_ENUM_STRUCT { Level; [switch_is(Level)] SESSION_ENUM_UNION }
    e.u32(SESSION_LEVEL_10); // Level
    e.u32(SESSION_LEVEL_10); // union discriminant (duplicates Level, per NDR)
    e.referent(); // Level10: LPSESSION_INFO_10_CONTAINER (non-null container on input)
    e.u32(0); //   EntriesRead = 0
    e.null_ptr(); //   Buffer = NULL

    e.u32(0xFFFF_FFFF); // PreferredMaximumLength (MAX_PREFERRED_LENGTH)
    e.null_ptr(); // ResumeHandle [in,out,unique] = NULL (single-shot)
    e.into_bytes()
}

/// Parse a `NetrSessionEnum` level-10 reply into its sessions.
/// Returns (sessions, total_entries, return_code).
pub fn decode_session_enum(stub: &[u8]) -> Result<(Vec<Session>, u32, u32)> {
    let mut d = NdrDecoder::new(stub);
    let level = d.u32()?; // Level (echoed)
    let tag = d.u32()?; // union discriminant
    if level != SESSION_LEVEL_10 || tag != SESSION_LEVEL_10 {
        return Err(RpcError::Protocol(format!(
            "NetrSessionEnum returned unexpected level/tag {level}/{tag}"
        )));
    }
    let container_ref = d.u32()?; // Level10 container [ref]
    let mut sessions = Vec::new();
    if container_ref != 0 {
        let entries_read = d.u32()? as usize;
        let buffer_ref = d.u32()?;
        if buffer_ref != 0 {
            let max_count = d.u32()? as usize; // conformant max_count
            if entries_read > max_count {
                return Err(RpcError::Protocol(format!(
                    "NetrSessionEnum EntriesRead={entries_read} exceeds max_count={max_count}"
                )));
            }
            // Fixed parts: EntriesRead × { cname ptr, user ptr, time, idle } — 16 wire bytes
            // per entry. Bound `entries_read` (attacker-controlled u32) against the remaining
            // stub before `Vec::with_capacity` so a hostile server sending
            // `entries_read = 0xFFFFFFFF` + a truncated tail can't request a multi-GB
            // allocation that aborts via `handle_alloc_error`.
            if entries_read
                .checked_mul(16)
                .map_or(true, |need| need > d.remaining())
            {
                return Err(crate::RpcError::Protocol(format!(
                    "NetrSessionEnum: EntriesRead={entries_read} exceeds remaining stub"
                )));
            }
            let mut refs = Vec::with_capacity(entries_read);
            for _ in 0..entries_read {
                let cname_ref = d.u32()?;
                let user_ref = d.u32()?;
                let _time = d.u32()?;
                let _idle = d.u32()?;
                refs.push((cname_ref, user_ref));
            }
            // Deferred: each string, in field order (cname then user), where the referent was set.
            for (cname_ref, user_ref) in refs {
                let client = if cname_ref != 0 {
                    d.conformant_varying_wstr()?
                } else {
                    String::new()
                };
                let user = if user_ref != 0 {
                    d.conformant_varying_wstr()?
                } else {
                    String::new()
                };
                sessions.push(Session { client, user });
            }
        }
    }
    let total_entries = d.u32()?;
    // ResumeHandle [in,out,unique]: a referent, then the value if non-null.
    let resume_ref = d.u32()?;
    if resume_ref != 0 {
        let _resume = d.u32()?;
    }
    let ret = d.u32()?;
    Ok((sessions, total_entries, ret))
}

/// One share as reported by `NetrShareEnum` level 1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// Share name (`shi1_netname`), e.g. `SYSVOL`, `NETLOGON`, `C$`, `IPC$`.
    pub netname: String,
    /// `shi1_type` — low byte is STYPE (0=disk, 1=printq, 2=device, 3=IPC);
    /// high bits `0x8000_0000` (special/admin `$`) and `0x4000_0000` (temporary).
    pub kind: u32,
    /// Free-text remark (`shi1_remark`).
    pub remark: String,
}

impl Share {
    /// True when the low STYPE byte marks this an administrative/special share
    /// (the `$` shares: `C$`, `ADMIN$`, `IPC$`).
    pub fn is_special(&self) -> bool {
        self.kind & 0x8000_0000 != 0
    }
    /// Human label for the low STYPE byte.
    pub fn stype_label(&self) -> &'static str {
        match self.kind & 0x00FF_FFFF {
            0 => "disk",
            1 => "printq",
            2 => "device",
            3 => "ipc",
            _ => "other",
        }
    }
}

/// Marshal a `NetrShareEnum(ServerName=NULL, Level=1, ...)` request.
/// Mirrors [`encode_session_enum`] but selects `SHARE_INFO_1` (netname/type/remark),
/// the level readable over an anonymous session on hosts that permit it.
pub fn encode_share_enum() -> Vec<u8> {
    let mut e = NdrEncoder::new();
    e.null_ptr(); // ServerName [in,string,unique] = NULL (server infers itself)

    // SHARE_ENUM_STRUCT { Level; [switch_is(Level)] SHARE_ENUM_UNION }
    e.u32(SHARE_LEVEL_1); // Level
    e.u32(SHARE_LEVEL_1); // union discriminant
    e.referent(); // Level1: LPSHARE_INFO_1_CONTAINER (non-null container on input)
    e.u32(0); //   EntriesRead = 0
    e.null_ptr(); //   Buffer = NULL

    e.u32(0xFFFF_FFFF); // PreferredMaximumLength (MAX_PREFERRED_LENGTH)
    e.null_ptr(); // ResumeHandle [in,out,unique] = NULL (single-shot)
    e.into_bytes()
}

/// Parse a `NetrShareEnum` level-1 reply into its shares.
/// Returns (shares, total_entries, return_code). Never panics on hostile input:
/// `EntriesRead` is bounded against the remaining stub before any allocation,
/// exactly as in [`decode_session_enum`].
pub fn decode_share_enum(stub: &[u8]) -> Result<(Vec<Share>, u32, u32)> {
    let mut d = NdrDecoder::new(stub);
    let level = d.u32()?; // Level (echoed)
    let tag = d.u32()?; // union discriminant
    if level != SHARE_LEVEL_1 || tag != SHARE_LEVEL_1 {
        return Err(RpcError::Protocol(format!(
            "NetrShareEnum returned unexpected level/tag {level}/{tag}"
        )));
    }
    let container_ref = d.u32()?; // Level1 container [ref]
    let mut shares = Vec::new();
    if container_ref != 0 {
        let entries_read = d.u32()? as usize;
        let buffer_ref = d.u32()?;
        if buffer_ref != 0 {
            let max_count = d.u32()? as usize; // conformant max_count
            if entries_read > max_count {
                return Err(RpcError::Protocol(format!(
                    "NetrShareEnum EntriesRead={entries_read} exceeds max_count={max_count}"
                )));
            }
            // Fixed part per SHARE_INFO_1: netname ptr (4) + type (4) + remark ptr (4)
            // = 12 wire bytes. Bound attacker-controlled `entries_read` against the
            // remaining stub before `Vec::with_capacity` (see decode_session_enum).
            if entries_read
                .checked_mul(12)
                .map_or(true, |need| need > d.remaining())
            {
                return Err(RpcError::Protocol(format!(
                    "NetrShareEnum: EntriesRead={entries_read} exceeds remaining stub"
                )));
            }
            let mut refs = Vec::with_capacity(entries_read);
            for _ in 0..entries_read {
                let netname_ref = d.u32()?;
                let kind = d.u32()?;
                let remark_ref = d.u32()?;
                refs.push((netname_ref, kind, remark_ref));
            }
            // Deferred strings in field order: netname then remark, where the referent was set.
            for (netname_ref, kind, remark_ref) in refs {
                let netname = if netname_ref != 0 {
                    d.conformant_varying_wstr()?
                } else {
                    String::new()
                };
                let remark = if remark_ref != 0 {
                    d.conformant_varying_wstr()?
                } else {
                    String::new()
                };
                shares.push(Share {
                    netname,
                    kind,
                    remark,
                });
            }
        }
    }
    let total_entries = d.u32()?;
    let resume_ref = d.u32()?;
    if resume_ref != 0 {
        let _resume = d.u32()?;
    }
    let ret = d.u32()?;
    Ok((shares, total_entries, ret))
}

/// High-level SRVSVC client bound over `\srvsvc`.
pub struct SrvsvcClient<'a> {
    pipe: SmbPipe<'a>,
}

impl<'a> SrvsvcClient<'a> {
    pub async fn bind(client: &'a mut SmbClient, file_id: [u8; 16]) -> Result<Self> {
        let mut pipe = SmbPipe::new(client, file_id);
        pipe.bind(srvsvc_syntax()).await?;
        Ok(SrvsvcClient { pipe })
    }

    /// Enumerate the host's logon sessions (level 10). A non-zero return code is surfaced to the
    /// caller alongside whatever entries were parsed.
    pub async fn enum_sessions(&mut self) -> Result<(Vec<Session>, u32)> {
        let resp = self
            .pipe
            .call(opnum::NETR_SESSION_ENUM, &encode_session_enum())
            .await?;
        let (sessions, _total, ret) = decode_session_enum(&resp)?;
        Ok((sessions, ret))
    }

    /// Enumerate the host's shares (level 1: netname/type/remark). A non-zero return
    /// code is surfaced alongside whatever entries were parsed. Over an anonymous
    /// session this is the classic share-listing primitive on hosts that permit it.
    pub async fn enum_shares(&mut self) -> Result<(Vec<Share>, u32)> {
        let resp = self
            .pipe
            .call(opnum::NETR_SHARE_ENUM, &encode_share_enum())
            .await?;
        let (shares, _total, ret) = decode_share_enum(&resp)?;
        Ok((shares, ret))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_selects_level_10_with_null_names() {
        let stub = encode_session_enum();
        // 3 null ptrs (ServerName/ClientName/UserName), then Level.
        assert_eq!(&stub[0..4], &0u32.to_le_bytes());
        assert_eq!(&stub[4..8], &0u32.to_le_bytes());
        assert_eq!(&stub[8..12], &0u32.to_le_bytes());
        assert_eq!(u32::from_le_bytes(stub[12..16].try_into().unwrap()), 10); // Level
        assert_eq!(u32::from_le_bytes(stub[16..20].try_into().unwrap()), 10); // union tag
    }

    // Hand-built (spec-shaped, NOT symmetric with the encoder) level-10 reply carrying one
    // session: WKSTN01\administrator. Validates the decoder's NDR walk against the MS-SRVS layout.
    // Live validation vs a real host is still owed (see the S2 plan).
    #[test]
    fn decodes_one_session_from_a_handbuilt_reply() {
        fn wstr(out: &mut Vec<u8>, s: &str) {
            let units: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
            out.extend_from_slice(&(units.len() as u32).to_le_bytes()); // max_count
            out.extend_from_slice(&0u32.to_le_bytes()); // offset
            out.extend_from_slice(&(units.len() as u32).to_le_bytes()); // actual_count
            for u in units {
                out.extend_from_slice(&u.to_le_bytes());
            }
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        let mut r = Vec::new();
        r.extend_from_slice(&10u32.to_le_bytes()); // Level
        r.extend_from_slice(&10u32.to_le_bytes()); // union tag
        r.extend_from_slice(&0x2_0000u32.to_le_bytes()); // container ref
        r.extend_from_slice(&1u32.to_le_bytes()); // EntriesRead
        r.extend_from_slice(&0x2_0004u32.to_le_bytes()); // Buffer ref
        r.extend_from_slice(&1u32.to_le_bytes()); // conformant max_count
                                                  // one SESSION_INFO_10 fixed part
        r.extend_from_slice(&0x2_0008u32.to_le_bytes()); // cname ref
        r.extend_from_slice(&0x2_000cu32.to_le_bytes()); // user ref
        r.extend_from_slice(&123u32.to_le_bytes()); // time
        r.extend_from_slice(&4u32.to_le_bytes()); // idle
        wstr(&mut r, "WKSTN01"); // deferred cname
        wstr(&mut r, "administrator"); // deferred user
        r.extend_from_slice(&1u32.to_le_bytes()); // TotalEntries
        r.extend_from_slice(&0u32.to_le_bytes()); // ResumeHandle ref = NULL
        r.extend_from_slice(&0u32.to_le_bytes()); // return code

        let (sessions, total, ret) = decode_session_enum(&r).unwrap();
        assert_eq!(ret, 0);
        assert_eq!(total, 1);
        assert_eq!(
            sessions,
            vec![Session {
                client: "WKSTN01".into(),
                user: "administrator".into()
            }]
        );
    }

    #[test]
    fn empty_reply_is_not_a_panic() {
        for cut in 0..24 {
            let _ = decode_session_enum(&vec![0u8; cut]);
        }
    }

    // Hostile server: valid header, container non-null, buffer non-null, then a
    // maliciously large EntriesRead followed by a truncated body. Must return
    // Err(Protocol) — NOT `Vec::with_capacity(0xFFFFFFFF)` → OOM abort.
    #[test]
    fn entries_read_is_bounded_against_stub() {
        let mut r = Vec::new();
        r.extend_from_slice(&10u32.to_le_bytes()); // Level
        r.extend_from_slice(&10u32.to_le_bytes()); // union tag
        r.extend_from_slice(&0x2_0000u32.to_le_bytes()); // container ref
        r.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // EntriesRead = u32::MAX
        r.extend_from_slice(&0x2_0004u32.to_le_bytes()); // Buffer ref
        r.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // conformant max_count
                                                            // (no body follows — server truncates here)
        let err = decode_session_enum(&r).unwrap_err();
        assert!(
            matches!(err, crate::RpcError::Protocol(ref s) if s.contains("EntriesRead")),
            "expected Protocol(EntriesRead …), got {err:?}"
        );
    }

    #[test]
    fn share_request_selects_level_1_with_null_server() {
        let stub = encode_share_enum();
        assert_eq!(&stub[0..4], &0u32.to_le_bytes()); // ServerName NULL
        assert_eq!(u32::from_le_bytes(stub[4..8].try_into().unwrap()), 1); // Level
        assert_eq!(u32::from_le_bytes(stub[8..12].try_into().unwrap()), 1); // union tag
    }

    // Hand-built (spec-shaped) level-1 reply carrying two shares: SYSVOL (disk) and
    // IPC$ (special/ipc). Validates the decoder's NDR walk + STYPE helpers.
    #[test]
    fn decodes_two_shares_from_a_handbuilt_reply() {
        fn wstr(out: &mut Vec<u8>, s: &str) {
            let units: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
            out.extend_from_slice(&(units.len() as u32).to_le_bytes()); // max_count
            out.extend_from_slice(&0u32.to_le_bytes()); // offset
            out.extend_from_slice(&(units.len() as u32).to_le_bytes()); // actual_count
            for u in units {
                out.extend_from_slice(&u.to_le_bytes());
            }
            while out.len() % 4 != 0 {
                out.push(0);
            }
        }
        let mut r = Vec::new();
        r.extend_from_slice(&1u32.to_le_bytes()); // Level
        r.extend_from_slice(&1u32.to_le_bytes()); // union tag
        r.extend_from_slice(&0x2_0000u32.to_le_bytes()); // container ref
        r.extend_from_slice(&2u32.to_le_bytes()); // EntriesRead
        r.extend_from_slice(&0x2_0004u32.to_le_bytes()); // Buffer ref
        r.extend_from_slice(&2u32.to_le_bytes()); // conformant max_count
                                                  // two SHARE_INFO_1 fixed parts
        r.extend_from_slice(&0x2_0008u32.to_le_bytes()); // [0] netname ref
        r.extend_from_slice(&0u32.to_le_bytes()); //         type = disk
        r.extend_from_slice(&0x2_000cu32.to_le_bytes()); // [0] remark ref
        r.extend_from_slice(&0x2_0010u32.to_le_bytes()); // [1] netname ref
        r.extend_from_slice(&0x8000_0003u32.to_le_bytes()); //  type = special|ipc
        r.extend_from_slice(&0u32.to_le_bytes()); //         [1] remark ref = NULL
        wstr(&mut r, "SYSVOL"); // [0] netname
        wstr(&mut r, "Logon server share"); // [0] remark
        wstr(&mut r, "IPC$"); // [1] netname
        r.extend_from_slice(&2u32.to_le_bytes()); // TotalEntries
        r.extend_from_slice(&0u32.to_le_bytes()); // ResumeHandle ref = NULL
        r.extend_from_slice(&0u32.to_le_bytes()); // return code

        let (shares, total, ret) = decode_share_enum(&r).unwrap();
        assert_eq!((total, ret), (2, 0));
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].netname, "SYSVOL");
        assert_eq!(shares[0].remark, "Logon server share");
        assert_eq!(shares[0].stype_label(), "disk");
        assert!(!shares[0].is_special());
        assert_eq!(shares[1].netname, "IPC$");
        assert_eq!(shares[1].remark, "");
        assert_eq!(shares[1].stype_label(), "ipc");
        assert!(shares[1].is_special());
    }

    #[test]
    fn share_empty_reply_is_not_a_panic() {
        for cut in 0..24 {
            let _ = decode_share_enum(&vec![0u8; cut]);
        }
    }

    #[test]
    fn share_entries_read_is_bounded_against_stub() {
        let mut r = Vec::new();
        r.extend_from_slice(&1u32.to_le_bytes()); // Level
        r.extend_from_slice(&1u32.to_le_bytes()); // union tag
        r.extend_from_slice(&0x2_0000u32.to_le_bytes()); // container ref
        r.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // EntriesRead = u32::MAX
        r.extend_from_slice(&0x2_0004u32.to_le_bytes()); // Buffer ref
        r.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // conformant max_count
        let err = decode_share_enum(&r).unwrap_err();
        assert!(
            matches!(err, crate::RpcError::Protocol(ref s) if s.contains("EntriesRead")),
            "expected Protocol(EntriesRead …), got {err:?}"
        );
    }
}
