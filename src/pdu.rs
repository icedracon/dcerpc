//! Connection-oriented DCE/RPC PDUs (MS-RPCE §2.2.6, DCE 1.1 §12.6). Little-endian DREP.

use crate::{ndr_transfer_syntax, Result, RpcError, Syntax};

pub mod ptype {
    pub const REQUEST: u8 = 0;
    pub const RESPONSE: u8 = 2;
    pub const FAULT: u8 = 3;
    pub const BIND: u8 = 11;
    pub const BIND_ACK: u8 = 12;
    pub const BIND_NAK: u8 = 13;
    pub const AUTH3: u8 = 16;
}

/// DCE/RPC authentication (MS-RPCE §2.2.2.11).
///
/// `RPC_C_AUTHN_WINNT` (NTLMSSP) and `RPC_C_AUTHN_GSS_KERBEROS` (SPNEGO/Kerberos AP-REQ)
/// are the two SSPs an on-wire dcerpc client currently emits; the level selects auth-only
/// vs sign+seal.
pub const RPC_C_AUTHN_WINNT: u8 = 0x0a;
pub const RPC_C_AUTHN_GSS_KERBEROS: u8 = 0x10;
pub const RPC_C_AUTHN_LEVEL_PKT_CONNECT: u8 = 0x02;
pub const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u8 = 0x06;

pub const PFC_FIRST_FRAG: u8 = 0x01;
pub const PFC_LAST_FRAG: u8 = 0x02;
const DREP_LE: [u8; 4] = [0x10, 0x00, 0x00, 0x00]; // little-endian, ASCII, IEEE float

/// 16-byte common header with `frag_length` patched in after the body is known.
fn header(ptype: u8, frag_length: u16, call_id: u32) -> Vec<u8> {
    header_auth(ptype, frag_length, 0, call_id)
}

/// 16-byte common header carrying a non-zero `auth_length` (length of the auth verifier's
/// auth_value, excluding the 8-byte sec_trailer).
fn header_auth(ptype: u8, frag_length: u16, auth_length: u16, call_id: u32) -> Vec<u8> {
    header_auth_flags(
        ptype,
        frag_length,
        auth_length,
        call_id,
        PFC_FIRST_FRAG | PFC_LAST_FRAG,
    )
}

fn header_auth_flags(
    ptype: u8,
    frag_length: u16,
    auth_length: u16,
    call_id: u32,
    pfc_flags: u8,
) -> Vec<u8> {
    let mut h = Vec::with_capacity(16);
    h.push(5); // rpc_vers
    h.push(0); // rpc_vers_minor
    h.push(ptype);
    h.push(pfc_flags);
    h.extend_from_slice(&DREP_LE);
    h.extend_from_slice(&frag_length.to_le_bytes());
    h.extend_from_slice(&auth_length.to_le_bytes());
    h.extend_from_slice(&call_id.to_le_bytes());
    h
}

fn wire_u16(value: usize, field: &str) -> Result<u16> {
    u16::try_from(value)
        .map_err(|_| RpcError::Protocol(format!("{field} {value} exceeds the DCE/RPC u16 limit")))
}

fn wire_u32(value: usize, field: &str) -> Result<u32> {
    u32::try_from(value)
        .map_err(|_| RpcError::Protocol(format!("{field} {value} exceeds the DCE/RPC u32 limit")))
}

/// The 8-byte sec_trailer that precedes the auth_value in an authenticated PDU.
fn sec_trailer(auth_pad_length: u8) -> [u8; 8] {
    sec_trailer_lvl(auth_pad_length, RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
}

/// `sec_trailer` with an explicit auth level — needed for relay flows that request
/// `PKT_CONNECT` (auth-only, no per-message signing/sealing), because the relaying attacker
/// doesn't hold the victim's NTLM session key and can't produce signatures.
pub(crate) fn sec_trailer_lvl(auth_pad_length: u8, auth_level: u8) -> [u8; 8] {
    sec_trailer_full(RPC_C_AUTHN_WINNT, auth_level, auth_pad_length)
}

/// `sec_trailer` with explicit auth_type + auth_level — the shared constructor for both the
/// NTLMSSP and Kerberos (`RPC_C_AUTHN_GSS_KERBEROS`) sealed-bind paths. `auth_context_id`
/// is a fixed 0 on this stack; Windows accepts any value on the client leg.
pub(crate) fn sec_trailer_full(auth_type: u8, auth_level: u8, auth_pad_length: u8) -> [u8; 8] {
    [auth_type, auth_level, auth_pad_length, 0, 0, 0, 0, 0]
}

fn bind_body(abstract_syntax: Syntax) -> Vec<u8> {
    let ndr = ndr_transfer_syntax();
    let mut body = Vec::new();
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_xmit_frag
    body.extend_from_slice(&5840u16.to_le_bytes()); // max_recv_frag
    body.extend_from_slice(&0u32.to_le_bytes()); // assoc_group_id
    body.push(1); // n_context_elem
    body.push(0);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
    body.push(1); // n_transfer_syn
    body.push(0);
    body.extend_from_slice(&abstract_syntax.uuid);
    body.extend_from_slice(&abstract_syntax.ver_major.to_le_bytes());
    body.extend_from_slice(&abstract_syntax.ver_minor.to_le_bytes());
    body.extend_from_slice(&ndr.uuid);
    body.extend_from_slice(&ndr.ver_major.to_le_bytes());
    body.extend_from_slice(&ndr.ver_minor.to_le_bytes());
    body
}

/// Build a BIND PDU offering one presentation context (abstract syntax + NDR transfer).
pub fn build_bind(call_id: u32, abstract_syntax: Syntax) -> Vec<u8> {
    try_build_bind(call_id, abstract_syntax).expect("BIND PDU length is fixed and valid")
}

/// Checked variant of [`build_bind`].
pub fn try_build_bind(call_id: u32, abstract_syntax: Syntax) -> Result<Vec<u8>> {
    let body = bind_body(abstract_syntax);
    let frag_length = wire_u16(16 + body.len(), "frag_length")?;
    let mut pdu = header(ptype::BIND, frag_length, call_id);
    pdu.extend_from_slice(&body);
    Ok(pdu)
}

/// BIND carrying an NTLM auth verifier (the NEGOTIATE token) for a sign+sealed session.
pub fn build_bind_auth(call_id: u32, abstract_syntax: Syntax, auth_token: &[u8]) -> Vec<u8> {
    try_build_bind_auth(call_id, abstract_syntax, auth_token)
        .expect("BIND auth token exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_bind_auth`].
pub fn try_build_bind_auth(
    call_id: u32,
    abstract_syntax: Syntax,
    auth_token: &[u8],
) -> Result<Vec<u8>> {
    let body = bind_body(abstract_syntax);
    let frag_length = wire_u16(16 + body.len() + 8 + auth_token.len(), "frag_length")?;
    let auth_length = wire_u16(auth_token.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::BIND, frag_length, auth_length, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer(0));
    pdu.extend_from_slice(auth_token);
    Ok(pdu)
}

/// [`build_bind_auth`] with an explicit auth level. For relay flows we ask for
/// `PKT_CONNECT` (auth-only) so subsequent calls need no per-message signing/sealing —
/// otherwise the middle attacker (who doesn't hold the victim's NTLM session key) can
/// authenticate but can't send any actual RPC calls.
pub fn build_bind_auth_level(
    call_id: u32,
    abstract_syntax: Syntax,
    auth_token: &[u8],
    auth_level: u8,
) -> Vec<u8> {
    try_build_bind_auth_level(call_id, abstract_syntax, auth_token, auth_level)
        .expect("BIND auth token exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_bind_auth_level`].
pub fn try_build_bind_auth_level(
    call_id: u32,
    abstract_syntax: Syntax,
    auth_token: &[u8],
    auth_level: u8,
) -> Result<Vec<u8>> {
    let body = bind_body(abstract_syntax);
    let frag_length = wire_u16(16 + body.len() + 8 + auth_token.len(), "frag_length")?;
    let auth_length = wire_u16(auth_token.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::BIND, frag_length, auth_length, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer_lvl(0, auth_level));
    pdu.extend_from_slice(auth_token);
    Ok(pdu)
}

/// [`build_auth3`] with an explicit auth level (see [`build_bind_auth_level`]).
pub fn build_auth3_level(call_id: u32, auth_token: &[u8], auth_level: u8) -> Vec<u8> {
    try_build_auth3_level(call_id, auth_token, auth_level)
        .expect("AUTH3 token exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_auth3_level`].
pub fn try_build_auth3_level(call_id: u32, auth_token: &[u8], auth_level: u8) -> Result<Vec<u8>> {
    let frag_length = wire_u16(16 + 4 + 8 + auth_token.len(), "frag_length")?;
    let auth_length = wire_u16(auth_token.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::AUTH3, frag_length, auth_length, call_id);
    pdu.extend_from_slice(&[0, 0, 0, 0]);
    pdu.extend_from_slice(&sec_trailer_lvl(0, auth_level));
    pdu.extend_from_slice(auth_token);
    Ok(pdu)
}

/// AUTH3 PDU carrying the NTLM AUTHENTICATE token — the final leg of the bind handshake.
pub fn build_auth3(call_id: u32, auth_token: &[u8]) -> Vec<u8> {
    try_build_auth3(call_id, auth_token).expect("AUTH3 token exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_auth3`].
pub fn try_build_auth3(call_id: u32, auth_token: &[u8]) -> Result<Vec<u8>> {
    // rpcconn_auth3: common header, a 4-byte pad (max_xmit/recv, ignored), then the verifier.
    let frag_length = wire_u16(16 + 4 + 8 + auth_token.len(), "frag_length")?;
    let auth_length = wire_u16(auth_token.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::AUTH3, frag_length, auth_length, call_id);
    pdu.extend_from_slice(&[0, 0, 0, 0]);
    pdu.extend_from_slice(&sec_trailer(0));
    pdu.extend_from_slice(auth_token);
    Ok(pdu)
}

/// BIND carrying a SPNEGO / Kerberos AP-REQ token (auth_type = `RPC_C_AUTHN_GSS_KERBEROS`).
///
/// The token itself is the GSS-API `InitialContextToken(SPNEGO → negTokenInit → krb5(AP-REQ))`
/// blob — built by a Kerberos crate holding the TGS session key. This function only frames it
/// as an RPC BIND with the given auth level (PKT_PRIVACY for sealed sessions).
pub fn build_bind_auth_kerberos(
    call_id: u32,
    abstract_syntax: Syntax,
    ap_req_gss_token: &[u8],
    auth_level: u8,
) -> Vec<u8> {
    try_build_bind_auth_kerberos(call_id, abstract_syntax, ap_req_gss_token, auth_level)
        .expect("Kerberos BIND token exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_bind_auth_kerberos`].
pub fn try_build_bind_auth_kerberos(
    call_id: u32,
    abstract_syntax: Syntax,
    ap_req_gss_token: &[u8],
    auth_level: u8,
) -> Result<Vec<u8>> {
    let body = bind_body(abstract_syntax);
    let frag_length = wire_u16(16 + body.len() + 8 + ap_req_gss_token.len(), "frag_length")?;
    let auth_length = wire_u16(ap_req_gss_token.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::BIND, frag_length, auth_length, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer_full(RPC_C_AUTHN_GSS_KERBEROS, auth_level, 0));
    pdu.extend_from_slice(ap_req_gss_token);
    Ok(pdu)
}

/// AUTH3 PDU completing a Kerberos bind. Windows normally answers BIND_ACK carrying an
/// AP-REP (mutual auth) and the client responds with an empty AUTH3 to close the exchange;
/// pass `&[]` for the empty case, or a follow-up token if one is required.
pub fn build_auth3_kerberos(call_id: u32, auth_token: &[u8], auth_level: u8) -> Vec<u8> {
    try_build_auth3_kerberos(call_id, auth_token, auth_level)
        .expect("Kerberos AUTH3 token exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_auth3_kerberos`].
pub fn try_build_auth3_kerberos(
    call_id: u32,
    auth_token: &[u8],
    auth_level: u8,
) -> Result<Vec<u8>> {
    let frag_length = wire_u16(16 + 4 + 8 + auth_token.len(), "frag_length")?;
    let auth_length = wire_u16(auth_token.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::AUTH3, frag_length, auth_length, call_id);
    pdu.extend_from_slice(&[0, 0, 0, 0]);
    pdu.extend_from_slice(&sec_trailer_full(RPC_C_AUTHN_GSS_KERBEROS, auth_level, 0));
    pdu.extend_from_slice(auth_token);
    Ok(pdu)
}

fn auth_verifier(buf: &[u8]) -> Result<Option<(&[u8], &[u8])>> {
    let (h, fragment) = validated_fragment(buf)?;
    let auth_length = h.auth_length as usize;
    if auth_length == 0 {
        return Ok(None);
    }
    let auth_start = fragment
        .len()
        .checked_sub(auth_length)
        .ok_or_else(|| RpcError::Protocol("auth_length exceeds fragment".into()))?;
    let trailer_start = auth_start
        .checked_sub(8)
        .ok_or_else(|| RpcError::Protocol("authentication verifier has no sec_trailer".into()))?;
    if trailer_start < 16 {
        return Err(RpcError::Protocol(
            "authentication verifier overlaps the PDU body".into(),
        ));
    }
    let trailer = &fragment[trailer_start..auth_start];
    if trailer[3] != 0 {
        return Err(RpcError::Protocol(format!(
            "authentication sec_trailer reserved byte is {}",
            trailer[3]
        )));
    }
    Ok(Some((trailer, &fragment[auth_start..])))
}

/// The auth_value is the trailing `auth_length` bytes after a validated sec_trailer.
pub fn extract_auth_value(buf: &[u8]) -> Result<Vec<u8>> {
    auth_verifier(buf)?
        .map(|(_, value)| value.to_vec())
        .ok_or_else(|| RpcError::Protocol("PDU carried no auth verifier".into()))
}

pub(crate) fn bind_ack_auth_value(
    buf: &[u8],
    expected_auth_type: u8,
    expected_auth_level: u8,
    required: bool,
) -> Result<Option<Vec<u8>>> {
    parse_bind_ack(buf, None)?;
    let Some((trailer, value)) = auth_verifier(buf)? else {
        if required {
            return Err(RpcError::Protocol(
                "authenticated BIND_ACK carried no auth verifier".into(),
            ));
        }
        return Ok(None);
    };
    if trailer[0] != expected_auth_type || trailer[1] != expected_auth_level {
        return Err(RpcError::Protocol(format!(
            "BIND_ACK auth metadata type={} level={} does not match expected type={expected_auth_type} level={expected_auth_level}",
            trailer[0], trailer[1]
        )));
    }
    if trailer[4..8] != [0, 0, 0, 0] {
        return Err(RpcError::Protocol(
            "BIND_ACK used an unexpected auth_context_id".into(),
        ));
    }
    Ok(Some(value.to_vec()))
}

pub(crate) fn reject_bind_ack_auth(buf: &[u8]) -> Result<()> {
    if auth_verifier(buf)?.is_some() {
        return Err(RpcError::Protocol(
            "unauthenticated BIND_ACK unexpectedly carried an auth verifier".into(),
        ));
    }
    Ok(())
}

/// Build a REQUEST PDU carrying an NDR-marshaled stub for `opnum`.
pub fn build_request(call_id: u32, p_cont_id: u16, opnum: u16, stub: &[u8]) -> Vec<u8> {
    try_build_request(call_id, p_cont_id, opnum, stub)
        .expect("request stub exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_request`].
pub fn try_build_request(call_id: u32, p_cont_id: u16, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
    try_build_request_fragment(
        call_id,
        p_cont_id,
        opnum,
        stub,
        wire_u32(stub.len(), "alloc_hint")?,
        PFC_FIRST_FRAG | PFC_LAST_FRAG,
    )
}

fn try_build_request_fragment(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    stub: &[u8],
    alloc_hint: u32,
    pfc_flags: u8,
) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(8 + stub.len());
    body.extend_from_slice(&alloc_hint.to_le_bytes());
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(stub);

    let frag_length = wire_u16(16 + body.len(), "frag_length")?;
    let mut pdu = header_auth_flags(ptype::REQUEST, frag_length, 0, call_id, pfc_flags);
    pdu.extend_from_slice(&body);
    Ok(pdu)
}

/// Build one or more unsealed REQUEST fragments respecting the negotiated peer limit.
pub fn try_build_request_fragments(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    stub: &[u8],
    max_fragment: usize,
) -> Result<Vec<Vec<u8>>> {
    if max_fragment > u16::MAX as usize {
        return Err(RpcError::Protocol(format!(
            "max_fragment {max_fragment} exceeds the DCE/RPC u16 limit"
        )));
    }
    let chunk_size = max_fragment.checked_sub(24).ok_or_else(|| {
        RpcError::Protocol(format!("max_fragment {max_fragment} is smaller than 24"))
    })?;
    if chunk_size == 0 && !stub.is_empty() {
        return Err(RpcError::Protocol(
            "max_fragment leaves no room for request stub data".into(),
        ));
    }
    let alloc_hint = wire_u32(stub.len(), "alloc_hint")?;
    if stub.is_empty() {
        return Ok(vec![try_build_request_fragment(
            call_id,
            p_cont_id,
            opnum,
            &[],
            alloc_hint,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
        )?]);
    }

    let chunk_count = stub.len().div_ceil(chunk_size);
    let mut fragments = Vec::with_capacity(chunk_count);
    for (index, chunk) in stub.chunks(chunk_size).enumerate() {
        let mut flags = 0;
        if index == 0 {
            flags |= PFC_FIRST_FRAG;
        }
        if index + 1 == chunk_count {
            flags |= PFC_LAST_FRAG;
        }
        fragments.push(try_build_request_fragment(
            call_id, p_cont_id, opnum, chunk, alloc_hint, flags,
        )?);
    }
    Ok(fragments)
}

/// Build a sign+sealed REQUEST PDU. `sealed_stub` is the already-RC4-sealed (stub‖pad),
/// `pad_len` the pad it contains, and `signature` the 16-byte NTLM MAC over the plaintext.
/// The request header fields (alloc_hint/cont_id/opnum) travel in the clear.
pub fn build_request_sealed(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    sealed_stub: &[u8],
    pad_len: u8,
    signature: &[u8],
    alloc_hint: u32,
) -> Vec<u8> {
    try_build_request_sealed(
        call_id,
        p_cont_id,
        opnum,
        sealed_stub,
        pad_len,
        signature,
        alloc_hint,
    )
    .expect("sealed request exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_request_sealed`].
#[allow(clippy::too_many_arguments)]
pub fn try_build_request_sealed(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    sealed_stub: &[u8],
    pad_len: u8,
    signature: &[u8],
    alloc_hint: u32,
) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(8 + sealed_stub.len());
    body.extend_from_slice(&alloc_hint.to_le_bytes());
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(sealed_stub);

    let frag_length = wire_u16(16 + body.len() + 8 + signature.len(), "frag_length")?;
    let auth_length = wire_u16(signature.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::REQUEST, frag_length, auth_length, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer(pad_len));
    pdu.extend_from_slice(signature);
    Ok(pdu)
}

/// As [`build_request_sealed`] but an ORPC (DCOM object) request: sets `PFC_OBJECT_UUID` and inserts
/// the 16-byte object UUID (the target interface's IPID) between the opnum and the stub. The stub
/// therefore begins at offset 40 (header 16 + alloc_hint 4 + p_cont_id 2 + opnum 2 + object 16).
#[allow(clippy::too_many_arguments)]
pub fn build_request_sealed_object(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    object: &[u8; 16],
    sealed_stub: &[u8],
    pad_len: u8,
    signature: &[u8],
    alloc_hint: u32,
) -> Vec<u8> {
    try_build_request_sealed_object(
        call_id,
        p_cont_id,
        opnum,
        object,
        sealed_stub,
        pad_len,
        signature,
        alloc_hint,
    )
    .expect("sealed object request exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_request_sealed_object`].
#[allow(clippy::too_many_arguments)]
pub fn try_build_request_sealed_object(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    object: &[u8; 16],
    sealed_stub: &[u8],
    pad_len: u8,
    signature: &[u8],
    alloc_hint: u32,
) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(24 + sealed_stub.len());
    body.extend_from_slice(&alloc_hint.to_le_bytes());
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(object); // ORPC object UUID (IPID)
    body.extend_from_slice(sealed_stub);

    let frag_length = wire_u16(16 + body.len() + 8 + signature.len(), "frag_length")?;
    let auth_length = wire_u16(signature.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::REQUEST, frag_length, auth_length, call_id);
    pdu[3] |= 0x80; // PFC_OBJECT_UUID
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer(pad_len));
    pdu.extend_from_slice(signature);
    Ok(pdu)
}

/// Build a sign+sealed REQUEST PDU for a Kerberos-authenticated session. Layout matches
/// [`build_request_sealed`] but the sec_trailer carries `RPC_C_AUTHN_GSS_KERBEROS`, and
/// `auth_value` is variable-length (28 B for AES-CTS-HMAC-SHA1-96 DCE-style: 16 B WRAP
/// header + 12 B checksum) rather than NTLM's fixed 16 B.
pub fn build_request_sealed_krb(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    sealed_stub: &[u8],
    pad_len: u8,
    auth_value: &[u8],
    alloc_hint: u32,
) -> Vec<u8> {
    try_build_request_sealed_krb(
        call_id,
        p_cont_id,
        opnum,
        sealed_stub,
        pad_len,
        auth_value,
        alloc_hint,
    )
    .expect("Kerberos sealed request exceeds the DCE/RPC PDU limit")
}

/// Checked variant of [`build_request_sealed_krb`].
#[allow(clippy::too_many_arguments)]
pub fn try_build_request_sealed_krb(
    call_id: u32,
    p_cont_id: u16,
    opnum: u16,
    sealed_stub: &[u8],
    pad_len: u8,
    auth_value: &[u8],
    alloc_hint: u32,
) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(8 + sealed_stub.len());
    body.extend_from_slice(&alloc_hint.to_le_bytes());
    body.extend_from_slice(&p_cont_id.to_le_bytes());
    body.extend_from_slice(&opnum.to_le_bytes());
    body.extend_from_slice(sealed_stub);

    let frag_length = wire_u16(16 + body.len() + 8 + auth_value.len(), "frag_length")?;
    let auth_length = wire_u16(auth_value.len(), "auth_length")?;
    let mut pdu = header_auth(ptype::REQUEST, frag_length, auth_length, call_id);
    pdu.extend_from_slice(&body);
    pdu.extend_from_slice(&sec_trailer_full(
        RPC_C_AUTHN_GSS_KERBEROS,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        pad_len,
    ));
    pdu.extend_from_slice(auth_value);
    Ok(pdu)
}

/// Split a sealed RESPONSE into (sealed_stub‖pad, signature), stripping the sec_trailer.
/// The caller unseals the stub and drops `auth_pad_length` trailing pad bytes.
pub fn split_sealed_response(buf: &[u8]) -> Result<(Vec<u8>, Vec<u8>, u8)> {
    let parsed = parse_sealed_response_any(buf, None, 24)?;
    Ok((
        parsed.sealed_stub.to_vec(),
        parsed.auth_value.to_vec(),
        parsed.pad_len,
    ))
}

/// Parsed common header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub ptype: u8,
    pub pfc_flags: u8,
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

pub fn parse_header(buf: &[u8]) -> Result<Header> {
    if buf.len() < 16 {
        return Err(RpcError::Underrun { need: 16, pos: 0 });
    }
    if buf[0] != 5 {
        return Err(RpcError::Protocol(format!("rpc_vers {} != 5", buf[0])));
    }
    if buf[1] > 1 {
        return Err(RpcError::Protocol(format!(
            "unsupported rpc_vers_minor {}",
            buf[1]
        )));
    }
    if buf[4..8] != DREP_LE {
        return Err(RpcError::Protocol(
            "unsupported DCE/RPC data representation".into(),
        ));
    }
    Ok(Header {
        ptype: buf[2],
        pfc_flags: buf[3],
        frag_length: u16::from_le_bytes([buf[8], buf[9]]),
        auth_length: u16::from_le_bytes([buf[10], buf[11]]),
        call_id: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
    })
}

/// Return the advertised length after validating that a complete fragment is present.
pub fn advertised_frag_length(buf: &[u8]) -> Result<usize> {
    let h = parse_header(buf)?;
    let frag = h.frag_length as usize;
    if frag < 16 {
        return Err(RpcError::Protocol(format!("frag_length {frag} < 16")));
    }
    if frag > buf.len() {
        return Err(RpcError::Underrun {
            need: frag,
            pos: buf.len(),
        });
    }
    Ok(frag)
}

fn validated_fragment(buf: &[u8]) -> Result<(Header, &[u8])> {
    let h = parse_header(buf)?;
    let frag = advertised_frag_length(buf)?;
    Ok((h, &buf[..frag]))
}

fn validate_call_id(h: Header, expected_call_id: Option<u32>) -> Result<()> {
    if let Some(expected) = expected_call_id {
        if h.call_id != expected {
            return Err(RpcError::Protocol(format!(
                "response call_id {} does not match request {expected}",
                h.call_id
            )));
        }
    }
    Ok(())
}

fn fault_status(fragment: &[u8]) -> Result<u32> {
    let status = fragment.get(24..28).ok_or(RpcError::Underrun {
        need: 28,
        pos: fragment.len(),
    })?;
    Ok(u32::from_le_bytes(
        status.try_into().expect("four-byte fault status"),
    ))
}

fn validate_response_prefix(fragment: &[u8]) -> Result<()> {
    if fragment.len() < 24 {
        return Err(RpcError::Underrun {
            need: 24,
            pos: fragment.len(),
        });
    }
    let p_cont_id = u16::from_le_bytes(fragment[20..22].try_into().unwrap());
    if p_cont_id != 0 {
        return Err(RpcError::Protocol(format!(
            "response used unexpected presentation context {p_cont_id}"
        )));
    }
    if fragment[23] != 0 {
        return Err(RpcError::Protocol(format!(
            "response reserved byte is non-zero ({:#04x})",
            fragment[23]
        )));
    }
    Ok(())
}

/// One validated unsealed RESPONSE fragment.
#[doc(hidden)]
pub struct PlainResponseFragment<'a> {
    pub pfc_flags: u8,
    pub frag_length: usize,
    pub stub: &'a [u8],
}

/// Validate and expose one unsealed RESPONSE fragment without allocating.
#[doc(hidden)]
pub fn parse_plain_response_fragment(
    buf: &[u8],
    expected_call_id: Option<u32>,
) -> Result<PlainResponseFragment<'_>> {
    let (h, fragment) = validated_fragment(buf)?;
    validate_call_id(h, expected_call_id)?;
    validate_response_prefix(fragment)?;
    match h.ptype {
        ptype::FAULT => Err(RpcError::Fault(fault_status(fragment)?)),
        ptype::RESPONSE => {
            if h.auth_length != 0 {
                return Err(RpcError::Protocol(format!(
                    "unsealed response carried auth_length {}",
                    h.auth_length
                )));
            }
            Ok(PlainResponseFragment {
                pfc_flags: h.pfc_flags,
                frag_length: fragment.len(),
                stub: &fragment[24..],
            })
        }
        other => Err(RpcError::UnexpectedPdu(other)),
    }
}

/// One validated authenticated RESPONSE fragment.
#[doc(hidden)]
pub struct SealedResponseFragment<'a> {
    pub pfc_flags: u8,
    pub frag_length: usize,
    pub stub_start: usize,
    pub fault_status: Option<u32>,
    /// PDU bytes covered by the SSP signature, including the security trailer but not auth_value.
    pub signed_pdu: &'a [u8],
    pub sealed_stub: &'a [u8],
    pub auth_value: &'a [u8],
    pub pad_len: u8,
}

fn parse_sealed_response_any(
    buf: &[u8],
    expected_call_id: Option<u32>,
    stub_start: usize,
) -> Result<SealedResponseFragment<'_>> {
    let (h, fragment) = validated_fragment(buf)?;
    validate_call_id(h, expected_call_id)?;
    validate_response_prefix(fragment)?;
    let (stub_start, fault_status) = match h.ptype {
        ptype::FAULT => (32, Some(fault_status(fragment)?)),
        ptype::RESPONSE => (stub_start, None),
        other => return Err(RpcError::UnexpectedPdu(other)),
    };

    let auth_length = h.auth_length as usize;
    // A FAULT PDU carrying only the fault_status field can legitimately arrive with
    // auth_length=0 — the server dropped the sealed reply because it stopped at fault time
    // and did not encrypt anything (observed on Windows Server 2019+ Task Scheduler
    // SchRpcRegisterTask). Return a fragment describing the fault so the transport layer
    // can propagate `RpcError::Fault(status)` instead of a misleading protocol error.
    if auth_length == 0 && matches!(h.ptype, ptype::FAULT) {
        return Ok(SealedResponseFragment {
            pfc_flags: h.pfc_flags,
            frag_length: fragment.len(),
            stub_start,
            fault_status,
            signed_pdu: fragment,
            sealed_stub: &[],
            auth_value: &[],
            pad_len: 0,
        });
    }
    if auth_length == 0 {
        return Err(RpcError::Protocol(
            "sealed response carried an empty auth_value".into(),
        ));
    }
    let minimum = stub_start
        .checked_add(8)
        .and_then(|n| n.checked_add(auth_length))
        .ok_or_else(|| RpcError::Protocol("sealed response length overflow".into()))?;
    if fragment.len() < minimum {
        return Err(RpcError::Underrun {
            need: minimum,
            pos: fragment.len(),
        });
    }
    let auth_start = fragment
        .len()
        .checked_sub(auth_length)
        .ok_or_else(|| RpcError::Protocol("auth_length exceeds fragment".into()))?;
    let sec_trailer_start = auth_start
        .checked_sub(8)
        .ok_or_else(|| RpcError::Protocol("missing security trailer".into()))?;
    if sec_trailer_start < stub_start {
        return Err(RpcError::Protocol(
            "security trailer overlaps the response header".into(),
        ));
    }
    let pad_len = fragment[sec_trailer_start + 2];
    if pad_len as usize > sec_trailer_start - stub_start {
        return Err(RpcError::Protocol(format!(
            "auth_pad_length {pad_len} exceeds sealed stub length {}",
            sec_trailer_start - stub_start
        )));
    }
    Ok(SealedResponseFragment {
        pfc_flags: h.pfc_flags,
        frag_length: fragment.len(),
        stub_start,
        fault_status,
        signed_pdu: &fragment[..auth_start],
        sealed_stub: &fragment[stub_start..sec_trailer_start],
        auth_value: &fragment[auth_start..],
        pad_len,
    })
}

/// Validate one authenticated response, including verifier type/level/length.
#[doc(hidden)]
pub fn parse_sealed_response_fragment(
    buf: &[u8],
    expected_call_id: u32,
    stub_start: usize,
    expected_auth_type: u8,
    expected_auth_length: usize,
) -> Result<SealedResponseFragment<'_>> {
    let parsed = parse_sealed_response_any(buf, Some(expected_call_id), stub_start)?;
    // A FAULT with empty auth_value carries no sec_trailer — the fault_status is the
    // payload. Skip the auth-type / auth-level / auth-context-id checks; those live in
    // the sec_trailer that this PDU shape simply doesn't have.
    if parsed.auth_value.is_empty() && parsed.fault_status.is_some() {
        return Ok(parsed);
    }
    let sec_trailer_start = parsed.signed_pdu.len() - 8;
    let trailer = &parsed.signed_pdu[sec_trailer_start..];
    if trailer[0] != expected_auth_type {
        return Err(RpcError::Protocol(format!(
            "unexpected auth_type {:#04x}, expected {expected_auth_type:#04x}",
            trailer[0]
        )));
    }
    if trailer[1] != RPC_C_AUTHN_LEVEL_PKT_PRIVACY {
        return Err(RpcError::Protocol(format!(
            "unexpected auth_level {:#04x} on sealed response",
            trailer[1]
        )));
    }
    if trailer[3] != 0 || trailer[4..8] != [0, 0, 0, 0] {
        return Err(RpcError::Protocol(
            "sealed response carried invalid reserved/auth_context_id metadata".into(),
        ));
    }
    if parsed.auth_value.len() != expected_auth_length {
        return Err(RpcError::Protocol(format!(
            "auth_length {} does not match expected {expected_auth_length}",
            parsed.auth_value.len()
        )));
    }
    Ok(parsed)
}

/// Negotiated fragment limits from a validated BIND_ACK.
#[derive(Debug, Clone, Copy)]
pub struct BindAck {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
}

/// Parse a BIND_ACK, including call id, presentation result and NDR transfer syntax.
pub fn parse_bind_ack(buf: &[u8], expected_call_id: Option<u32>) -> Result<BindAck> {
    let (h, fragment) = validated_fragment(buf)?;
    validate_call_id(h, expected_call_id)?;
    if h.ptype == ptype::BIND_NAK {
        let reason = fragment
            .get(16..18)
            .map(|b| u16::from_le_bytes(b.try_into().expect("two-byte reject reason")));
        return Err(RpcError::Protocol(match reason {
            Some(r) => format!("BIND_NAK reject_reason={r}"),
            None => "BIND_NAK (no reason field)".to_string(),
        }));
    }
    if h.ptype != ptype::BIND_ACK {
        return Err(RpcError::UnexpectedPdu(h.ptype));
    }
    if h.pfc_flags & (PFC_FIRST_FRAG | PFC_LAST_FRAG) != (PFC_FIRST_FRAG | PFC_LAST_FRAG) {
        return Err(RpcError::Protocol(
            "fragmented BIND_ACK is not supported".into(),
        ));
    }

    let auth_length = h.auth_length as usize;
    let (body_end, auth_pad_length) = if auth_length == 0 {
        // Some Windows DCs (verified: Server 2025 DC01 on Kerberos-PKT_PRIVACY BINDs)
        // append an 8-byte sec_trailer to the BIND_ACK even when the auth verifier
        // itself is empty — acknowledging the negotiated auth_type + auth_level with
        // no AP-REP. Detect that suffix and consume it: valid sec_trailer signature is
        // a known auth_type + PKT_CONNECT/INTEGRITY/PRIVACY level + zero reserved bytes.
        let n = fragment.len();
        if n >= 8 {
            let trailer = &fragment[n - 8..];
            let known_type = matches!(
                trailer[0],
                RPC_C_AUTHN_WINNT | RPC_C_AUTHN_GSS_KERBEROS | 0x00 | 0x09 | 0x0e | 0x44
            );
            let known_level = matches!(trailer[1], 0x01..=0x06);
            let reserved_zero = trailer[3] == 0 && trailer[4..8] == [0u8; 4];
            if known_type && known_level && reserved_zero {
                (n - 8, trailer[2] as usize)
            } else {
                (n, 0usize)
            }
        } else {
            (n, 0usize)
        }
    } else {
        let auth_start = fragment
            .len()
            .checked_sub(auth_length)
            .ok_or_else(|| RpcError::Protocol("BIND_ACK auth_length exceeds fragment".into()))?;
        let trailer_start = auth_start.checked_sub(8).ok_or_else(|| {
            RpcError::Protocol("BIND_ACK authentication verifier has no sec_trailer".into())
        })?;
        let trailer = &fragment[trailer_start..auth_start];
        if trailer[3] != 0 {
            return Err(RpcError::Protocol(format!(
                "BIND_ACK sec_trailer reserved byte is {}",
                trailer[3]
            )));
        }
        (trailer_start, trailer[2] as usize)
    };
    if body_end < 30 {
        return Err(RpcError::Underrun {
            need: 30,
            pos: body_end,
        });
    }
    let max_xmit_frag = u16::from_le_bytes(fragment[16..18].try_into().unwrap());
    let max_recv_frag = u16::from_le_bytes(fragment[18..20].try_into().unwrap());
    if max_xmit_frag < 24 || max_recv_frag < 24 {
        return Err(RpcError::Protocol(format!(
            "invalid negotiated fragment sizes xmit={max_xmit_frag}, recv={max_recv_frag}"
        )));
    }
    let sec_addr_len = u16::from_le_bytes(fragment[24..26].try_into().unwrap()) as usize;
    let mut cursor = 26usize
        .checked_add(sec_addr_len)
        .ok_or_else(|| RpcError::Protocol("BIND_ACK secondary address overflow".into()))?;
    cursor = cursor
        .checked_add(3)
        .ok_or_else(|| RpcError::Protocol("BIND_ACK alignment overflow".into()))?
        & !3;
    if cursor + 4 > body_end {
        return Err(RpcError::Underrun {
            need: cursor + 4,
            pos: body_end,
        });
    }
    let result_count = fragment[cursor] as usize;
    cursor += 4;
    if result_count != 1 || cursor + 24 > body_end {
        return Err(RpcError::Protocol(format!(
            "BIND_ACK carried {result_count} presentation results; expected exactly one"
        )));
    }
    let result = u16::from_le_bytes(fragment[cursor..cursor + 2].try_into().unwrap());
    let reason = u16::from_le_bytes(fragment[cursor + 2..cursor + 4].try_into().unwrap());
    if result != 0 {
        return Err(RpcError::Protocol(format!(
            "BIND presentation context rejected: result={result}, reason={reason}"
        )));
    }
    let ndr = ndr_transfer_syntax();
    if fragment[cursor + 4..cursor + 20] != ndr.uuid
        || fragment[cursor + 20..cursor + 22] != ndr.ver_major.to_le_bytes()
        || fragment[cursor + 22..cursor + 24] != ndr.ver_minor.to_le_bytes()
    {
        return Err(RpcError::Protocol(
            "BIND_ACK selected an unexpected transfer syntax".into(),
        ));
    }
    let result_end = cursor + 24;
    if result_end.checked_add(auth_pad_length) != Some(body_end) {
        return Err(RpcError::Protocol(format!(
            "BIND_ACK body has {} trailing bytes but sec_trailer declares {auth_pad_length} bytes of auth padding",
            body_end - result_end
        )));
    }
    Ok(BindAck {
        max_xmit_frag,
        max_recv_frag,
    })
}

/// Confirm a BIND_ACK and its accepted NDR presentation context.
pub fn expect_bind_ack(buf: &[u8]) -> Result<()> {
    parse_bind_ack(buf, None).map(|_| ())
}

/// Extract the stub data from a RESPONSE PDU, or translate a FAULT into an error.
/// Response layout: 16-byte header + alloc_hint(4) + p_cont_id(2) + cancel_count(1) + reserved(1).
pub fn parse_response(buf: &[u8]) -> Result<Vec<u8>> {
    let parsed = parse_plain_response_fragment(buf, None)?;
    if parsed.pfc_flags & PFC_LAST_FRAG == 0 {
        return Err(RpcError::Protocol(
            "fragmented response requires transport reassembly".into(),
        ));
    }
    Ok(parsed.stub.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_header_shape() {
        let samr = Syntax::new("12345778-1234-abcd-ef00-0123456789ac", 1, 0);
        let pdu = build_bind(1, samr);
        assert_eq!(pdu[0], 5); // rpc_vers
        assert_eq!(pdu[2], ptype::BIND);
        assert_eq!(pdu[3], PFC_FIRST_FRAG | PFC_LAST_FRAG);
        let frag = u16::from_le_bytes([pdu[8], pdu[9]]) as usize;
        assert_eq!(frag, pdu.len());
        let h = parse_header(&pdu).unwrap();
        assert_eq!(h.ptype, ptype::BIND);
        assert_eq!(h.call_id, 1);
    }

    #[test]
    fn request_carries_opnum_and_stub() {
        let stub = [0xDE, 0xAD, 0xBE, 0xEF];
        let pdu = build_request(7, 0, 0x0005, &stub);
        assert_eq!(pdu[2], ptype::REQUEST);
        // opnum sits at header(16) + alloc_hint(4) + p_cont_id(2) = offset 22
        assert_eq!(u16::from_le_bytes([pdu[22], pdu[23]]), 0x0005);
        assert_eq!(&pdu[24..28], &stub);
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
    }

    #[test]
    fn bind_auth_carries_verifier() {
        let drs = Syntax::new("e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4, 0);
        let token = [0xAAu8; 40];
        let pdu = build_bind_auth(3, drs, &token);
        assert_eq!(pdu[2], ptype::BIND);
        assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), token.len() as u16); // auth_length
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len()); // frag_length
                                                                              // sec_trailer sits right before the token: auth_type=WINNT, level=PKT_PRIVACY.
        let st = pdu.len() - token.len() - 8;
        assert_eq!(pdu[st], RPC_C_AUTHN_WINNT);
        assert_eq!(pdu[st + 1], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(&pdu[pdu.len() - token.len()..], &token);
        // extract_auth_value recovers the token (models pulling the CHALLENGE off a BIND_ACK).
        assert_eq!(extract_auth_value(&pdu).unwrap(), token);
    }

    #[test]
    fn auth3_shape() {
        let token = [0xBBu8; 120];
        let pdu = build_auth3(4, &token);
        assert_eq!(pdu[2], ptype::AUTH3);
        assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), token.len() as u16);
        assert_eq!(&pdu[16..20], &[0, 0, 0, 0]); // the 4-byte pad
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
    }

    #[test]
    fn sealed_request_response_split_roundtrips() {
        let sealed = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let sig = [0x09u8; 16];
        let req = build_request_sealed(9, 0, 3, &sealed, 0, &sig, sealed.len() as u32);
        assert_eq!(req[2], ptype::REQUEST);
        assert_eq!(u16::from_le_bytes([req[10], req[11]]), 16); // auth_length = signature
        assert_eq!(u16::from_le_bytes([req[8], req[9]]) as usize, req.len());
        // Turn it into a RESPONSE shape and split it back.
        let mut resp = req.clone();
        resp[2] = ptype::RESPONSE;
        let (s, g, pad) = split_sealed_response(&resp).unwrap();
        assert_eq!(s, sealed);
        assert_eq!(g, sig);
        assert_eq!(pad, 0);
    }

    #[test]
    fn bind_auth_kerberos_marks_gss_type() {
        let drs = Syntax::new("e3514235-4b06-11d1-ab04-00c04fc2dcd2", 4, 0);
        // Realistic AP-REQ SPNEGO wrapper is ~1.4 KB; a 900-byte placeholder is enough to
        // exercise the auth_length + sec_trailer plumbing.
        let token = vec![0xC5u8; 900];
        let pdu = build_bind_auth_kerberos(9, drs, &token, RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(pdu[2], ptype::BIND);
        assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), token.len() as u16);
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
        let st = pdu.len() - token.len() - 8;
        assert_eq!(pdu[st], RPC_C_AUTHN_GSS_KERBEROS);
        assert_eq!(pdu[st + 1], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(&pdu[pdu.len() - token.len()..], &token[..]);
    }

    #[test]
    fn auth3_kerberos_carries_gss_type() {
        // A completing AUTH3 for Kerberos can legitimately be empty (the AP-REP came in the
        // BIND_ACK and no further token is needed); verify the frame is well-formed anyway.
        let pdu = build_auth3_kerberos(11, &[], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(pdu[2], ptype::AUTH3);
        assert_eq!(u16::from_le_bytes([pdu[10], pdu[11]]), 0);
        assert_eq!(u16::from_le_bytes([pdu[8], pdu[9]]) as usize, pdu.len());
        // sec_trailer sits right after the 4-byte pad.
        assert_eq!(pdu[20], RPC_C_AUTHN_GSS_KERBEROS);
        assert_eq!(pdu[21], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
    }

    #[test]
    fn request_sealed_krb_variable_auth_len() {
        // AES-CTS-HMAC-SHA1-96 DCE-style: 16 B WRAP header + 12 B HMAC = 28 B auth_value —
        // wider than NTLM's fixed 16 B, so the framer must respect the passed length.
        let sealed = [0xEEu8; 12];
        let auth_value = [0x77u8; 28];
        let req = build_request_sealed_krb(3, 0, 0x1234, &sealed, 0, &auth_value, 12);
        assert_eq!(req[2], ptype::REQUEST);
        assert_eq!(u16::from_le_bytes([req[10], req[11]]), 28);
        assert_eq!(u16::from_le_bytes([req[8], req[9]]) as usize, req.len());
        // sec_trailer sits between the stub and the auth_value.
        let st = req.len() - auth_value.len() - 8;
        assert_eq!(req[st], RPC_C_AUTHN_GSS_KERBEROS);
        assert_eq!(req[st + 1], RPC_C_AUTHN_LEVEL_PKT_PRIVACY);
        assert_eq!(&req[req.len() - auth_value.len()..], &auth_value[..]);
    }

    #[test]
    fn parse_response_extracts_stub() {
        // Fake a RESPONSE: 24-byte prefix then stub.
        let mut pdu = build_request(1, 0, 0, &[]); // reuse header shape
        pdu[2] = ptype::RESPONSE;
        pdu.truncate(16);
        pdu.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // alloc_hint+cont+cancel+reserved
        pdu.extend_from_slice(&[0x11, 0x22]); // stub
        let frag = pdu.len() as u16;
        pdu[8..10].copy_from_slice(&frag.to_le_bytes());
        assert_eq!(parse_response(&pdu).unwrap(), vec![0x11, 0x22]);
    }

    #[test]
    fn checked_request_rejects_length_past_u16() {
        let largest = vec![0x41; u16::MAX as usize - 24];
        assert_eq!(try_build_request(1, 0, 0, &largest).unwrap().len(), 65535);
        let too_large = vec![0x41; largest.len() + 1];
        assert!(try_build_request(1, 0, 0, &too_large).is_err());
    }

    #[test]
    fn request_fragmentation_preserves_stub_and_flags() {
        let stub: Vec<u8> = (0..200).map(|n| n as u8).collect();
        let fragments = try_build_request_fragments(17, 0, 9, &stub, 80).unwrap();
        assert_eq!(fragments.len(), 4);
        let mut rebuilt = Vec::new();
        for (index, fragment) in fragments.iter().enumerate() {
            assert!(fragment.len() <= 80);
            assert_eq!(parse_header(fragment).unwrap().call_id, 17);
            let flags = fragment[3];
            assert_eq!(flags & PFC_FIRST_FRAG != 0, index == 0);
            assert_eq!(flags & PFC_LAST_FRAG != 0, index == fragments.len() - 1);
            assert_eq!(
                u32::from_le_bytes(fragment[16..20].try_into().unwrap()),
                200
            );
            rebuilt.extend_from_slice(&fragment[24..]);
        }
        assert_eq!(rebuilt, stub);
    }

    #[test]
    fn checked_auth_builder_rejects_oversized_token() {
        let syntax = Syntax::new("12345778-1234-abcd-ef00-0123456789ac", 1, 0);
        assert!(try_build_bind_auth(1, syntax, &vec![0u8; 65536]).is_err());
    }

    #[test]
    fn response_rejects_short_or_truncated_fragment() {
        let mut response = header(ptype::RESPONSE, 23, 1);
        response.resize(23, 0);
        assert!(parse_response(&response).is_err());

        let mut truncated = header(ptype::RESPONSE, 32, 1);
        truncated.resize(24, 0);
        assert!(parse_response(&truncated).is_err());
    }

    #[test]
    fn sealed_response_rejects_hostile_auth_length() {
        let mut response = header_auth(ptype::RESPONSE, 32, u16::MAX, 7);
        response.resize(32, 0);
        assert!(split_sealed_response(&response).is_err());
    }

    #[test]
    fn sealed_fault_is_structurally_parsed_before_status_is_trusted() {
        let mut fault = header_auth(ptype::FAULT, 56, 16, 7);
        fault.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        fault.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        fault.extend_from_slice(&[0, 0]); // cancel_count, reserved
        fault.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // status
        fault.extend_from_slice(&[0u8; 4]); // reserved2
        fault.extend_from_slice(&sec_trailer(0));
        fault.extend_from_slice(&[0x55; 16]);
        let parsed = parse_sealed_response_fragment(&fault, 7, 24, RPC_C_AUTHN_WINNT, 16).unwrap();
        assert_eq!(parsed.stub_start, 32);
        assert_eq!(parsed.fault_status, Some(0xDEAD_BEEF));
        assert!(parsed.sealed_stub.is_empty());
    }

    #[test]
    fn fault_with_empty_auth_value_is_propagated_not_rejected() {
        // Windows Server 2019+ Task Scheduler responds to a sealed SchRpcRegisterTask
        // failure with a FAULT PDU carrying only the fault_status (auth_length=0, no
        // sec_trailer, no auth_value). Pre-fix, dcerpc bailed with a misleading
        // "sealed response carried an empty auth_value" protocol error and callers
        // never learned the real HRESULT — `attack atexec` in adhammer surfaced this
        // gap. Post-fix, the FAULT flows through with the fault_status intact.
        let mut fault = header_auth(ptype::FAULT, 32, 0, 7);
        fault.extend_from_slice(&0u32.to_le_bytes()); // alloc_hint
        fault.extend_from_slice(&0u16.to_le_bytes()); // p_cont_id
        fault.extend_from_slice(&[0, 0]); // cancel_count, reserved
        fault.extend_from_slice(&0xC00000ACu32.to_le_bytes()); // status = STATUS_PIPE_BUSY-ish
        fault.extend_from_slice(&[0u8; 4]); // reserved2
        let parsed = parse_sealed_response_fragment(&fault, 7, 24, RPC_C_AUTHN_WINNT, 16)
            .expect("FAULT with auth_length=0 must be structurally accepted");
        assert_eq!(parsed.fault_status, Some(0xC00000AC));
        assert!(parsed.auth_value.is_empty());
        assert!(parsed.sealed_stub.is_empty());
    }

    #[test]
    fn response_rejects_unexpected_context_and_reserved_byte() {
        let mut response = header(ptype::RESPONSE, 24, 1);
        response.resize(24, 0);
        response[20..22].copy_from_slice(&1u16.to_le_bytes());
        assert!(parse_response(&response).is_err());
        response[20..22].copy_from_slice(&0u16.to_le_bytes());
        response[23] = 1;
        assert!(parse_response(&response).is_err());
    }

    #[test]
    fn response_rejects_wrong_call_id() {
        let mut response = header(ptype::RESPONSE, 24, 8);
        response.resize(24, 0);
        assert!(parse_plain_response_fragment(&response, Some(7)).is_err());
    }

    #[test]
    fn bind_ack_validates_context_and_limits() {
        let ndr = ndr_transfer_syntax();
        let mut body = Vec::new();
        body.extend_from_slice(&5840u16.to_le_bytes());
        body.extend_from_slice(&5840u16.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes()); // empty secondary address
        body.extend_from_slice(&[0, 0]); // align result list to four bytes
        body.extend_from_slice(&[1, 0, 0, 0]); // one result
        body.extend_from_slice(&0u16.to_le_bytes()); // acceptance
        body.extend_from_slice(&0u16.to_le_bytes()); // reason
        body.extend_from_slice(&ndr.uuid);
        body.extend_from_slice(&ndr.ver_major.to_le_bytes());
        body.extend_from_slice(&ndr.ver_minor.to_le_bytes());
        let frag = u16::try_from(16 + body.len()).unwrap();
        let mut ack = header(ptype::BIND_ACK, frag, 9);
        ack.extend_from_slice(&body);

        let parsed = parse_bind_ack(&ack, Some(9)).unwrap();
        assert_eq!(parsed.max_recv_frag, 5840);
        assert!(parse_bind_ack(&ack, Some(10)).is_err());
        assert!(reject_bind_ack_auth(&ack).is_ok());

        let mut auth_ack = ack.clone();
        let token = [0xAA, 0xBB, 0xCC, 0xDD];
        let trailer_start = auth_ack.len();
        auth_ack.extend_from_slice(&sec_trailer(0));
        auth_ack.extend_from_slice(&token);
        let auth_frag = u16::try_from(auth_ack.len()).unwrap();
        auth_ack[8..10].copy_from_slice(&auth_frag.to_le_bytes());
        auth_ack[10..12].copy_from_slice(&(token.len() as u16).to_le_bytes());
        assert_eq!(
            bind_ack_auth_value(
                &auth_ack,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                true,
            )
            .unwrap(),
            Some(token.to_vec())
        );
        assert!(reject_bind_ack_auth(&auth_ack).is_err());
        assert!(bind_ack_auth_value(
            &auth_ack,
            RPC_C_AUTHN_GSS_KERBEROS,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            true,
        )
        .is_err());
        auth_ack[trailer_start + 4] = 1;
        assert!(bind_ack_auth_value(
            &auth_ack,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            true,
        )
        .is_err());
        auth_ack[trailer_start + 4] = 0;
        auth_ack[trailer_start + 2] = 1;
        assert!(parse_bind_ack(&auth_ack, Some(9)).is_err());

        ack[32..34].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse_bind_ack(&ack, Some(9)).is_err());
    }
}
