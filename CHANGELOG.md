# Changelog

All notable changes to `dcerpc` will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
project adheres to [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing pending.

## [0.2.10] — 2026-09-06

### Documentation

- README bumped 0.2.8 → 0.2.9 (was stale after 0.2.9 shipped) and now
  0.2.10; "What's new in 0.2.8" section split so 0.2.9's `NetrShareEnum`
  addition appears alongside prior history.
- Qualify the "live-validated" bullet: it excludes TSCH
  `SchRpcRegisterTask`, which remains experimental
  (`nca_s_fault_ndr` on Server 2025). The caveat was already documented
  four bullets down; the top-line claim now points to it inline.

No code changes.

## [0.2.9] — 2026-08-31

### Added

- `srvsvc::NetrShareEnum` (opnum 15, `SHARE_INFO_1`) with the same
  allocation-bound discipline as the existing `NetSessionEnum`.

## [0.2.8] — 2026-08-27

### Security

- Validate authenticated RESPONSE fragment structure before security-trailer arithmetic across
  TCP/SMB and NTLM/Kerberos paths; reject hostile `auth_length`, padding, auth type/level, call ID,
  PFC sequence and incomplete-fragment inputs.
- Add default connect, I/O and whole-call deadlines plus 64 MiB/4096-fragment response budgets.
- Replace silently truncating PDU length casts with checked builders used by both transports.
- Reject short RPRN/DCOM/interface replies instead of panicking or reporting implicit success.
- Remove environment-triggered raw DRS and decrypted supplemental-credential dumps.

### Fixed

- Fragment oversized unsealed requests at the negotiated peer limit and reassemble fragmented
  unsealed responses over TCP and SMB. Oversized sealed requests now fail explicitly instead of
  emitting malformed/truncated wire lengths.
- Validate BIND presentation acceptance, negotiated fragment sizes, NDR transfer syntax, and
  authenticated reply provider/level/padding/context metadata.
- Attempt SVCCTL service and TSCH task cleanup on every post-creation error path, and surface
  cleanup failures.
- Reject overlong Netlogon restore cleartext instead of silently truncating it.
- Tighten RRP/SAMR/SRVSVC return-status and varying-array validation.

### Testing

- Add regression tests for oversized PDU lengths, malformed fragment lengths, hostile auth
  lengths, call-ID mismatch, rejected BIND contexts, RPRN/DCOM short replies and Netlogon bounds.
- Add fuzz targets for PDU/BIND framing, DCOM STDOBJREF, RPRN status, ICPR responses, DRS replies
  and Kerberos key parsing.

## [0.2.7] — 2026-08-23 *(committed local, not yet published)*

### Added — WS-4 Kerberos sealed bind, Phase 1 (offline primitives)

- `pdu::RPC_C_AUTHN_GSS_KERBEROS` constant (0x10) and internal
  `sec_trailer_full(auth_type, auth_level, pad_len)` factoring, so the same
  sec_trailer builder serves both NTLMSSP and Kerberos paths.
- `pdu::build_bind_auth_kerberos`, `pdu::build_auth3_kerberos`,
  `pdu::build_request_sealed_krb` — RPC PDU framers that stamp
  `auth_type = 0x10` and carry a variable-length auth_value (28 B for
  AES-CTS-HMAC-SHA1-96 DCE-style vs NTLM's fixed 16 B).
- `krb_seal` module: RFC 4121 §4.2.6 `WrapToken` header codec (encode +
  decode with reserved-flag / filler / TOK_ID enforcement) and the
  `KrbSealer` trait matching `ntlmssp::SealState`'s `seal_pdu` /
  `unseal_pdu` shape but returning a variable auth_value. Concrete AES-CTS
  crypto (`DK` + n-fold + `E()` + DCE-style WRAP layout) lives outside this
  crate — a Kerberos crate holding the TGS session key wires it up via
  `picky-krb`'s `Aes256CtsHmacSha196` cipher.
- Hostile-input tests: short header, wrong TOK_ID, reserved flag bits set,
  bad filler, `u16::MAX` RRC, wrong auth_value length — all rejected
  without allocation.

### Added — WS-4 Kerberos sealed transport

- `RpcTcp::bind_sealed_kerberos`, `SmbPipe::bind_sealed_kerberos`, and their sealed call paths
  wire the Phase 1 framing to a caller-provided `KrbSealer`. TGT/TGS acquisition and the concrete
  cipher implementation remain outside this transport crate.

## [0.2.6] — 2026-08-20 *(committed local, not yet published)*

### Added
- `fuzz/` — cargo-fuzz workspace with 8 targets: srvsvc_decode,
  wkssvc_decode, samr_enum_domains, samr_lookup_domain,
  lsat_lookup_names, rrp_query_value, rrp_query_info_class,
  rrp_enum_key. libFuzzer only runs on Linux (WSL Kali here).

### Fixed
- `samr::decode_enum_domains` bounded-alloc preflight
  (`entries × 12` vs remaining stub). Discovered by
  `samr_enum_domains` fuzz target within ~15 s of first run;
  regression test uses the exact 24-byte crash artifact.
- `lsat::decode_lookup_names` bounded-alloc preflight
  (`entries × 12` vs remaining stub). Same fuzz-driven discovery path.

## [0.2.5] — 2026-08-20

### Added
- `dcerpc::wkssvc` — MS-WKST `NetrWkstaUserEnum` level 1 client
  (logged-on-user enumeration, needs local admin).
- `dcerpc::rrp::logged_on_sids` — HKU registry walk returning loaded-profile SIDs.

### Fixed
- `wkssvc::decode_wksta_user_enum` — `entries_read × 16` bounded-alloc
  preflight against remaining stub. Regression test with `0xFFFFFFFF`
  input asserts `RpcError::Protocol`.

### Docs
- Stripped third-party tool names from wire-format dev-note comments
  (byte-diff comparison notes rewritten as MS-* spec citations).

## [0.2.4] — 2026-08-18

### Fixed
- Three bounded-alloc preflights closing DoS from hostile `u32`
  attacker-controlled sizes:
  - `srvsvc::decode_session_enum` — `entries_read × 16` preflight.
  - `rrp::decode_query_info_class` — `actual × 2` preflight.
  - `rrp::decode_enum_key` — `actual × 2` preflight.

## [0.2.3] — 2026-08-10

### Fixed
- Dropped `ms-nrpc` reverse-dep to break the `dcerpc ↔ ms-nrpc`
  resolver cycle (0.2.2 was yanked for the same reason). Netlogon
  primitives restored as inline defensive code inside `netlogon.rs`;
  full-fat `ms-nrpc` remains available as standalone.

## [0.2.2] — 2026-08-09 [YANKED]

Yanked due to cyclic version resolution: `ms-nrpc = "0.1.0-dev"` fed
back through `dcerpc = "0.2"` created a resolver loop. Replaced by
0.2.3 which drops the ms-nrpc reverse dep.

## [0.2.1] — 2026-08-06

### Added
- ICPR / DCOM / DCOM-WMI stubs for AD CS + WMI-exec flows.
- Sealed named-pipe bind via NTLM sign+seal.

### Fixed
- Assorted NDR alignment corner cases uncovered by live-DC validation.

## [0.2.0] — 2026-08-02

### Changed
- Extracted NDR marshaling into its own [`ms-ndr`](https://crates.io/crates/ms-ndr)
  crate; `dcerpc` now re-exports via a thin shim for backward compat.
- API surface stabilised on the four primary interfaces
  (SRVSVC / RRP / SAMR / LSAT).

## [0.1.0] — 2026-07-28

Initial release: hand-rolled NDR encoder/decoder, DCE/RPC PDU framing,
NTLMSSP sign+seal transport, EPM port-mapping, initial SRVSVC/SAMR/LSAT/
RRP clients over SMB2 named pipes.
