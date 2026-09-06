# dcerpc

[![Crates.io](https://img.shields.io/crates/v/dcerpc.svg)](https://crates.io/crates/dcerpc)
[![Docs.rs](https://docs.rs/dcerpc/badge.svg)](https://docs.rs/dcerpc)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A pure-Rust, **no-FFI** DCE/RPC (MS-RPCE) stack — hand-rolled NDR marshaling, connection-oriented
PDUs, **NTLMSSP and Kerberos sign+seal** for packet privacy, and both TCP (`ncacn_ip_tcp`) and SMB named-pipe
(`ncacn_np`) transports. On top of the transport: the endpoint mapper (EPM) plus clients for a
dozen Windows MS-RPC interfaces (SAMR, LSAT, DRSUAPI, SVCCTL, TSCH, EFSR, RPRN, ICPR, SRVSVC,
FSRVP, DFSNM, RRP, Netlogon, DCOM/WMI).

Together with [`smb2-client`](https://crates.io/crates/smb2-client),
[`ntlmssp`](https://crates.io/crates/ntlmssp) and [`ms-ndr`](https://crates.io/crates/ms-ndr),
this is the pure-Rust AD protocol toolkit that didn't otherwise exist — usable from Linux/macOS against a
Windows domain, static-linkable, one binary.

## Status

**`0.2.9`** — actively developed. Part of the
[icedracon Rust offensive AD ecosystem](https://github.com/icedracon) and dogfooded by
[`adhammer`](https://crates.io/crates/adhammer).

### What's new in 0.2.9

- `srvsvc::NetrShareEnum` (opnum 15, `SHARE_INFO_1`) with the same allocation-bound
  discipline as the existing `NetSessionEnum`.

### 0.2.8

- Strict PDU, BIND_ACK, presentation-context, call-ID and authenticated security-trailer
  validation for hostile or malformed RPC peers.
- Bounded TCP/SMB response streams with connect, I/O and whole-call deadlines plus aggregate
  byte and fragment limits.
- Kerberos and NTLM sealed calls over both TCP and SMB named pipes.
- Panic-free short-reply handling for RPRN/DCOM and strict status decoding across interface
  clients; transient SVCCTL services and TSCH tasks now clean up on error paths.
- Six additional fuzz targets for framing, DCOM, RPRN, ICPR and DRS parsing.

## What it does

`dcerpc` is a layered stack you can either drive at the interface level (the high-level clients)
or hand-roll against directly (the PDU / NDR / transport primitives, useful when the interface
you need isn't shipped).

```text
[ ncacn_ip_tcp  |  ncacn_np (SMB named pipe via smb2-client) ]       transport
[ bind · alter-context · request · response · fault ]                 pdu
[ NDR (via ms-ndr): alignment · c-v arrays · unique ptrs · UTF-16 ]   ndr
[ NTLMSSP or Kerberos sign+seal — auth_level PKT_PRIVACY ]           seal
[ interface clients: SAMR · LSAT · DRSUAPI · SVCCTL · … ]             api
```

## Usage

### SAMR — enumerate domain users over an authenticated SMB pipe

```rust
use dcerpc::samr::SamrClient;
use smb2_client::SmbClient;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let mut smb = SmbClient::connect("dc.corp.local:445").await?;
smb.login("dc.corp.local", "CORP", "alice", "P@ssw0rd").await?;
smb.tree_connect(r"\\dc.corp.local\IPC$").await?;
let pipe = smb.open_pipe("samr").await?;
let mut samr = SamrClient::bind(&mut smb, pipe).await?;
for (rid, name) in samr.enumerate_all_users(r"\\dc.corp.local").await? {
    println!("{rid}\t{name}");
}
# Ok(()) }
```

### Zerologon safe-detect (CVE-2020-1472, non-destructive)

```rust
use dcerpc::netlogon::{detect_zerologon, Zerologon};

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
match detect_zerologon("10.10.10.22", "DC01", 2000).await? {
    Zerologon::Vulnerable { attempts } => {
        println!("VULNERABLE after {attempts} attempts (safe-detect only, no reset)")
    }
    Zerologon::NotVulnerable { attempts } => {
        println!("not vulnerable after {attempts} attempts")
    }
}
# Ok(()) }
```

`detect_zerologon` sends `NetrServerReqChallenge` + `NetrServerAuthenticate3` with the all-zero
authenticator described in Secura's original PoC and reads back the `ret_status` — it never
touches `NetrServerPasswordSet2`, so the DC's machine account is never zeroed. For the
destructive path (adhammer's `attack zerologon` after user confirmation), see
`exploit_set_empty_password` + the two `restore_password*` variants in the same module.

## Interfaces shipped

| Module | Interface (UUID) | Notable use |
|--------|------------------|-------------|
| `samr`     | `12345778-1234-abcd-ef00-0123456789ac` | SAMR — enumerate domain/users/groups/admins |
| `lsat`     | `12345778-1234-abcd-ef00-0123456789ab` | LSAT — name ↔ SID lookup, LookupNames/LookupSids |
| `drsuapi`  | `e3514235-4b06-11d1-ab04-00c04fc2dcd2` | DCSync (`DRSGetNCChanges`) — **deprecated 0.2.1**, moved to [`ms-drsr`](https://crates.io/crates/ms-drsr); removal in `0.4.0` |
| `svcctl`   | `367abb81-9844-35f1-ad32-98f038001003` | Service create/start/stop — the psexec-style RCE path |
| `tsch`     | `86d35949-83c9-4044-b424-db363231fd0c` | Task Scheduler XML — `atexec`-style RCE |
| `efsr`     | `c681d488-d850-11d0-8c52-00c04fd90f7e` | EFSR — PetitPotam coercion (`EfsRpcOpenFileRaw`) |
| `rprn`     | `12345678-1234-abcd-ef00-0123456789ab` | Print System (SpoolSs) — PrinterBug coercion |
| `icpr`     | `91ae6020-9e3c-11cf-8d7c-00aa00c091be` | AD CS enrollment (`CertServerRequest`) — ESC1 |
| `srvsvc`   | `4b324fc8-1670-01d3-1278-5a47bf6ee188` | Session enum, share enum |
| `wkssvc`   | `6bffd098-a112-3610-9833-46c3f87e345a` | WKST — `NetrWkstaUserEnum` logged-on users (level 1; requires local admin) |
| `fsrvp`    | `a8e0653c-2744-4389-a61d-7373df8b2292` | File Server Remote VSS Protocol — snapshot creation |
| `dfsnm`    | `4fc742e0-4a10-11cf-8273-00aa004ae673` | DFS namespace management |
| `rrp`      | `338cd001-2244-31f1-aaaa-900038001003` | Windows Remote Registry — ADCS ESC6/7/10/11/16 detection; `logged_on_sids()` via HKU |
| `netlogon` | `12345678-1234-abcd-ef00-01234567cffb` | Zerologon safe-detect + destructive writers |
| `dcom` / `dcom_wmi` | `4d9f4ab8-7d1c-11cf-861e-0020af6e7c57` (OXID) + WMI | DCOM activation → OXID resolve → `IWbemServices::ExecMethod Win32_Process.Create` |

Every module carries an `opnum` submodule with the canonical opcodes, an `encode_*`/`decode_*`
pair per opnum you can drive yourself, and (where async makes sense) a higher-level `*Client`
that owns the pipe/transport.

## What works / what does not (this version)

- ✅ Full RPC bind with `PKT_PRIVACY` (NTLMSSP sign+seal) over both TCP and SMB named pipes.
- ✅ EPM `ept_map` to resolve dynamic ports.
- ✅ Interfaces above are byte-tested against protocol specs and live-validated against
  fully-patched Windows Server 2022 / 2025 lab DCs — **except TSCH `SchRpcRegisterTask`**,
  which stays experimental (`nca_s_fault_ndr` on Server 2025; see the caveat below).
- ✅ DCOM/WMI activation → `Win32_Process.Create` with pass-the-hash support.
- ⚠ The in-crate `drsuapi` implementation is deprecated — new code should depend on
  [`ms-drsr`](https://crates.io/crates/ms-drsr) directly. Will be removed in `0.4.0`.
- ⚠ Only `PKT_PRIVACY` (sign+seal) is exercised. `PKT_INTEGRITY` (sign-only) is not on the
  hot path for the interfaces shipped, so it's not wired.
- ⚠ Kerberos BIND and per-message sealing are supported through the `KrbSealer` trait; acquiring
  the TGS and providing the concrete Kerberos cryptography remain caller responsibilities.
- ⚠ TSCH `SchRpcRegisterTask` remains experimental: the current Server 2025 lab returns
  `nca_s_fault_ndr`. Prefer SVCCTL for validated remote execution until that wire mismatch is fixed.

## Related icedracon crates

- [`ms-ndr`](https://crates.io/crates/ms-ndr) — the NDR transfer syntax primitives this crate
  builds on (aligned primitives, conformant/varying arrays, referent pointers, UTF-16LE
  c-v strings).
- [`ntlmssp`](https://crates.io/crates/ntlmssp) — NTLMv2 + MIC + key-exch + RC4 sign+seal used
  for the RPC auth layer.
- [`smb2-client`](https://crates.io/crates/smb2-client) — async SMB2 client that carries the
  `ncacn_np` named-pipe transport (with `TCP_NODELAY` — ~12× faster on small-request paths).
- [`ms-nrpc`](https://crates.io/crates/ms-nrpc) — defensive Netlogon byte-level primitives now
  re-exported by `dcerpc::netlogon`.
- [`ms-drsr`](https://crates.io/crates/ms-drsr) — the extracted DRSUAPI/DCSync module.
- [`ms-icpr`](https://crates.io/crates/ms-icpr) — the extracted ICPR (AD CS) enrollment client
  with an offline CSR builder.
- [`windows-sddl`](https://crates.io/crates/windows-sddl) — `Sid`/`Guid` types + security-
  descriptor parser used by SAMR/LSAT decoders.
- [`adhammer`](https://crates.io/crates/adhammer) — the AD security-assessment toolkit that
  drives this stack end-to-end.

## License

MIT © 2026 [zevs](https://github.com/icedracon). Extracted from
[ADhammer](https://github.com/icedracon/adhammer).

Authorized-testing / research / education use only.
