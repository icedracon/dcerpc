//! ncacn_ip_tcp and SMB named-pipe transports with bounded, strict response reassembly.

use crate::{pdu, Result, RpcError, Syntax};
use ntlmssp::{Ntlm, SealState};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, timeout_at, Instant};

/// Availability limits applied to every transport operation and response stream.
#[derive(Clone, Copy, Debug)]
pub struct TransportLimits {
    pub connect_timeout: Duration,
    pub io_timeout: Duration,
    pub call_timeout: Duration,
    pub max_response_bytes: usize,
    pub max_response_fragments: usize,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            io_timeout: Duration::from_secs(30),
            call_timeout: Duration::from_secs(120),
            max_response_bytes: 64 * 1024 * 1024,
            max_response_fragments: 4096,
        }
    }
}

fn timeout_error(operation: &str) -> RpcError {
    RpcError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        format!("{operation} timed out"),
    ))
}

struct ResponseBudget {
    deadline: Instant,
    max_bytes: usize,
    max_fragments: usize,
    bytes: usize,
    fragments: usize,
}

impl ResponseBudget {
    fn new(limits: TransportLimits) -> Self {
        Self {
            deadline: Instant::now() + limits.call_timeout,
            max_bytes: limits.max_response_bytes,
            max_fragments: limits.max_response_fragments,
            bytes: 0,
            fragments: 0,
        }
    }

    fn observe(&mut self, frag_length: usize, pfc_flags: u8) -> Result<()> {
        if self.fragments == 0 {
            if pfc_flags & pdu::PFC_FIRST_FRAG == 0 {
                return Err(RpcError::Protocol(
                    "response stream did not start with PFC_FIRST_FRAG".into(),
                ));
            }
        } else if pfc_flags & pdu::PFC_FIRST_FRAG != 0 {
            return Err(RpcError::Protocol(
                "non-initial response fragment repeated PFC_FIRST_FRAG".into(),
            ));
        }
        self.fragments = self
            .fragments
            .checked_add(1)
            .ok_or_else(|| RpcError::Protocol("response fragment counter overflow".into()))?;
        if self.fragments > self.max_fragments {
            return Err(RpcError::Protocol(format!(
                "response exceeded {} fragments",
                self.max_fragments
            )));
        }
        self.bytes = self
            .bytes
            .checked_add(frag_length)
            .ok_or_else(|| RpcError::Protocol("response byte counter overflow".into()))?;
        if self.bytes > self.max_bytes {
            return Err(RpcError::Protocol(format!(
                "response exceeded {} bytes",
                self.max_bytes
            )));
        }
        Ok(())
    }

    fn ensure_buffered(&self, buffered: usize) -> Result<()> {
        if self
            .bytes
            .checked_add(buffered)
            .map_or(true, |total| total > self.max_bytes)
        {
            return Err(RpcError::Protocol(format!(
                "response exceeded {} bytes",
                self.max_bytes
            )));
        }
        Ok(())
    }
}

fn bounded_deadline(call_deadline: Instant, io_timeout: Duration) -> Instant {
    let io_deadline = Instant::now() + io_timeout;
    if io_deadline < call_deadline {
        io_deadline
    } else {
        call_deadline
    }
}

pub struct RpcTcp {
    stream: TcpStream,
    call_id: u32,
    seal: Option<SealState>,
    session_key: Option<[u8; 16]>,
    /// The call_id of an in-flight relayed BIND — carried between
    /// [`bind_relay_start`](RpcTcp::bind_relay_start) and
    /// [`bind_relay_finish`](RpcTcp::bind_relay_finish).
    pending_relay_bind: Option<u32>,
    /// Kerberos sealer (mutually exclusive with `seal`), set when the connection
    /// was bound via `bind_sealed_kerberos`. Owns the trait object so the concrete
    /// crypto impl stays outside this crate.
    krb_seal: Option<Box<dyn crate::krb_seal::KrbSealer + Send>>,
    limits: TransportLimits,
    max_request_frag: usize,
}

impl RpcTcp {
    pub async fn connect(addr: &str) -> Result<Self> {
        Self::connect_with_limits(addr, TransportLimits::default()).await
    }

    /// Connect with explicit transport availability limits.
    pub async fn connect_with_limits(addr: &str, limits: TransportLimits) -> Result<Self> {
        // Routes through the process-global SOCKS5 proxy if set (addr already carries the port).
        let stream = timeout(limits.connect_timeout, smb2_client::socks::dial(addr, 135))
            .await
            .map_err(|_| timeout_error("RPC TCP connect"))??;
        Ok(RpcTcp {
            stream,
            call_id: 1,
            seal: None,
            session_key: None,
            pending_relay_bind: None,
            krb_seal: None,
            limits,
            max_request_frag: 5840,
        })
    }

    /// Replace limits for subsequent calls on this connection.
    pub fn set_limits(&mut self, limits: TransportLimits) {
        self.limits = limits;
    }

    /// The negotiated NTLM exported session key — the base key for DRSUAPI secret decryption.
    pub fn session_key(&self) -> Option<[u8; 16]> {
        self.session_key
    }

    async fn send(&mut self, buf: &[u8]) -> Result<()> {
        self.send_until(buf, Instant::now() + self.limits.io_timeout)
            .await
    }

    async fn send_until(&mut self, buf: &[u8], call_deadline: Instant) -> Result<()> {
        timeout_at(
            bounded_deadline(call_deadline, self.limits.io_timeout),
            self.stream.write_all(buf),
        )
        .await
        .map_err(|_| timeout_error("RPC TCP write"))??;
        Ok(())
    }

    /// Read exactly one PDU (16-byte header, then `frag_length - 16` more bytes).
    async fn recv_until(&mut self, call_deadline: Instant) -> Result<Vec<u8>> {
        let mut head = [0u8; 16];
        timeout_at(
            bounded_deadline(call_deadline, self.limits.io_timeout),
            self.stream.read_exact(&mut head),
        )
        .await
        .map_err(|_| timeout_error("RPC TCP read header"))??;
        let frag = u16::from_le_bytes([head[8], head[9]]) as usize;
        if frag < 16 {
            return Err(RpcError::Protocol(format!("frag_length {frag} < 16")));
        }
        let mut rest = vec![0u8; frag - 16];
        timeout_at(
            bounded_deadline(call_deadline, self.limits.io_timeout),
            self.stream.read_exact(&mut rest),
        )
        .await
        .map_err(|_| timeout_error("RPC TCP read body"))??;
        let mut pdu = head.to_vec();
        pdu.append(&mut rest);
        Ok(pdu)
    }

    async fn recv(&mut self) -> Result<Vec<u8>> {
        self.recv_until(Instant::now() + self.limits.io_timeout)
            .await
    }

    fn next_call_id(&mut self) -> u32 {
        let id = self.call_id;
        self.call_id = self.call_id.wrapping_add(1);
        id
    }

    fn accept_bind_ack(&mut self, buf: &[u8], call_id: u32) -> Result<()> {
        let ack = pdu::parse_bind_ack(buf, Some(call_id))?;
        self.max_request_frag = ack.max_recv_frag as usize;
        Ok(())
    }

    fn ensure_request_fits(&self, request_len: usize) -> Result<()> {
        if request_len > self.max_request_frag {
            return Err(RpcError::Protocol(format!(
                "request PDU is {request_len} bytes, exceeding negotiated max_recv_frag {}; request fragmentation is required",
                self.max_request_frag
            )));
        }
        Ok(())
    }

    /// Bind the given abstract syntax (interface) over this connection.
    pub async fn bind(&mut self, syntax: Syntax) -> Result<()> {
        let call_id = self.next_call_id();
        let bind = pdu::try_build_bind(call_id, syntax)?;
        self.send(&bind).await?;
        let resp = self.recv().await?;
        self.accept_bind_ack(&resp, call_id)?;
        pdu::reject_bind_ack_auth(&resp)
    }

    /// Issue one request for `opnum` with an NDR stub; return the response stub bytes.
    pub async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        let call_id = self.next_call_id();
        let requests =
            pdu::try_build_request_fragments(call_id, 0, opnum, stub, self.max_request_frag)?;
        let mut budget = ResponseBudget::new(self.limits);
        for request in requests {
            self.send_until(&request, budget.deadline).await?;
        }
        let mut plain = Vec::new();
        loop {
            let resp = self.recv_until(budget.deadline).await?;
            let parsed = pdu::parse_plain_response_fragment(&resp, Some(call_id))?;
            budget.observe(parsed.frag_length, parsed.pfc_flags)?;
            plain.extend_from_slice(parsed.stub);
            if parsed.pfc_flags & pdu::PFC_LAST_FRAG != 0 {
                return Ok(plain);
            }
        }
    }

    /// Authenticated bind with NTLMSSP sign+seal (auth_level PKT_PRIVACY). Runs the three-leg
    /// handshake (BIND → BIND_ACK/CHALLENGE → AUTH3) and arms the [`SealState`] so subsequent
    /// [`call_sealed`](Self::call_sealed) requests are encrypted. Required for DRSUAPI, which a
    /// DC refuses to answer on an unsealed channel.
    pub async fn bind_sealed(
        &mut self,
        syntax: Syntax,
        domain: &str,
        user: &str,
        password: &str,
        workstation: &str,
    ) -> Result<()> {
        let ntlm = Ntlm::new_sealed();
        // The BIND and its AUTH3 completion share one call_id (they are one negotiation).
        let bind_call_id = self.next_call_id();
        let bind = pdu::try_build_bind_auth(bind_call_id, syntax, ntlm.negotiate())?;
        self.send(&bind).await?;
        let ack = self.recv().await?;
        self.accept_bind_ack(&ack, bind_call_id)?;
        let challenge = pdu::bind_ack_auth_value(
            &ack,
            pdu::RPC_C_AUTHN_WINNT,
            pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            true,
        )?
        .ok_or_else(|| RpcError::Protocol("NTLM BIND_ACK verifier disappeared".into()))?;
        let (type3, exported) = ntlm
            .authenticate(&challenge, domain, user, password, workstation)
            .map_err(|e| RpcError::Protocol(format!("ntlm authenticate: {e}")))?;
        let auth3 = pdu::try_build_auth3(bind_call_id, &type3)?;
        self.send(&auth3).await?; // AUTH3 is unacknowledged
        self.session_key = Some(exported);
        self.seal = Some(SealState::new(&exported));
        Ok(())
    }

    /// As [`bind_sealed`](Self::bind_sealed) but pass-the-hash: authenticate with a raw NT hash
    /// instead of a plaintext password.
    pub async fn bind_sealed_hash(
        &mut self,
        syntax: Syntax,
        domain: &str,
        user: &str,
        nt_hash: &[u8; 16],
        workstation: &str,
    ) -> Result<()> {
        let ntlm = Ntlm::new_sealed();
        let bind_call_id = self.next_call_id();
        let bind = pdu::try_build_bind_auth(bind_call_id, syntax, ntlm.negotiate())?;
        self.send(&bind).await?;
        let ack = self.recv().await?;
        self.accept_bind_ack(&ack, bind_call_id)?;
        let challenge = pdu::bind_ack_auth_value(
            &ack,
            pdu::RPC_C_AUTHN_WINNT,
            pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            true,
        )?
        .ok_or_else(|| RpcError::Protocol("NTLM BIND_ACK verifier disappeared".into()))?;
        let (type3, exported) = ntlm
            .authenticate_hash(&challenge, domain, user, nt_hash, workstation)
            .map_err(|e| RpcError::Protocol(format!("ntlm authenticate (hash): {e}")))?;
        let auth3 = pdu::try_build_auth3(bind_call_id, &type3)?;
        self.send(&auth3).await?;
        self.session_key = Some(exported);
        self.seal = Some(SealState::new(&exported));
        Ok(())
    }

    /// Relay-mode BIND, step 1: send the victim's NTLM `Type1` (NEGOTIATE) opaquely and
    /// return the server's `Type2` (CHALLENGE) for the caller to forward back to the victim.
    /// Uses auth-level `PKT_CONNECT` (auth-only) — the middle attacker doesn't hold the
    /// victim's NTLM session key, so per-message signing/sealing cannot be performed.
    /// Subsequent RPC calls MUST go through [`call`](Self::call) (unsealed).
    ///
    /// Whether the target service accepts CONNECT-level auth is a per-interface, per-server
    /// config: MS-ICPR on many CA hosts does; DRSUAPI on a DC does not.
    pub async fn bind_relay_start(
        &mut self,
        syntax: Syntax,
        victim_type1: &[u8],
    ) -> Result<Vec<u8>> {
        let bind_call_id = self.next_call_id();
        let bind = pdu::try_build_bind_auth_level(
            bind_call_id,
            syntax,
            victim_type1,
            pdu::RPC_C_AUTHN_LEVEL_PKT_CONNECT,
        )?;
        self.send(&bind).await?;
        let ack = self.recv().await?;
        self.accept_bind_ack(&ack, bind_call_id)?;
        let type2 = pdu::bind_ack_auth_value(
            &ack,
            pdu::RPC_C_AUTHN_WINNT,
            pdu::RPC_C_AUTHN_LEVEL_PKT_CONNECT,
            true,
        )?
        .ok_or_else(|| RpcError::Protocol("relay BIND_ACK verifier disappeared".into()))?;
        self.pending_relay_bind = Some(bind_call_id);
        Ok(type2)
    }

    /// Relay-mode BIND, step 2: send the victim's NTLM `Type3` (AUTHENTICATE) opaquely to
    /// complete the authentication. After this returns, subsequent [`call`](Self::call)
    /// requests are made in the victim's context — provided the interface accepts
    /// CONNECT-level auth (see [`bind_relay_start`](Self::bind_relay_start)).
    pub async fn bind_relay_finish(&mut self, victim_type3: &[u8]) -> Result<()> {
        let bind_call_id = self
            .pending_relay_bind
            .take()
            .ok_or_else(|| RpcError::Protocol("bind_relay_finish without _start".into()))?;
        let auth3 = pdu::try_build_auth3_level(
            bind_call_id,
            victim_type3,
            pdu::RPC_C_AUTHN_LEVEL_PKT_CONNECT,
        )?;
        self.send(&auth3).await?; // AUTH3 is unacknowledged
        Ok(())
    }

    /// Kerberos sign+seal BIND for ncacn_ip_tcp (port 135 / EPM-resolved). Mirror of
    /// [`SmbPipe::bind_sealed_kerberos`] — parameters and semantics are identical, only the
    /// underlying transport differs.
    pub async fn bind_sealed_kerberos(
        &mut self,
        syntax: Syntax,
        ap_req_gss_token: &[u8],
        sealer: Box<dyn crate::krb_seal::KrbSealer + Send>,
    ) -> Result<()> {
        let bind_call_id = self.next_call_id();
        let bind = pdu::try_build_bind_auth_kerberos(
            bind_call_id,
            syntax,
            ap_req_gss_token,
            pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        )?;
        self.send(&bind).await?;
        let ack = self.recv().await?;
        self.accept_bind_ack(&ack, bind_call_id)?;
        pdu::bind_ack_auth_value(
            &ack,
            pdu::RPC_C_AUTHN_GSS_KERBEROS,
            pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            false,
        )?;
        let auth3 =
            pdu::try_build_auth3_kerberos(bind_call_id, &[], pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY)?;
        self.send(&auth3).await?;
        self.krb_seal = Some(sealer);
        Ok(())
    }

    /// Kerberos sealed request over a TCP-bound session. Mirrors
    /// [`SmbPipe::call_sealed_kerberos`].
    pub async fn call_sealed_kerberos(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        const STUB_OFF: usize = 24;
        let pad_len = ((4 - (stub.len() % 4)) % 4) as u8;
        let mut stub_padded = stub.to_vec();
        stub_padded.extend(std::iter::repeat(0u8).take(pad_len as usize));

        let auth_value_len = self
            .krb_seal
            .as_ref()
            .ok_or_else(|| RpcError::Protocol("session not kerberos-sealed".into()))?
            .auth_value_len();

        let call_id = self.next_call_id();
        let alloc_hint = u32::try_from(stub.len())
            .map_err(|_| RpcError::Protocol("request stub exceeds u32 alloc_hint".into()))?;
        let placeholder_av = vec![0u8; auth_value_len];
        let mut req = pdu::try_build_request_sealed_krb(
            call_id,
            0,
            opnum,
            &stub_padded,
            pad_len,
            &placeholder_av,
            alloc_hint,
        )?;
        self.ensure_request_fits(req.len())?;
        let n = req.len();
        let sign_over = req[..n - auth_value_len].to_vec();
        let sealer = self
            .krb_seal
            .as_mut()
            .ok_or_else(|| RpcError::Protocol("session not kerberos-sealed".into()))?;
        let (sealed, auth_value) = sealer.seal_pdu(&sign_over, &stub_padded);
        if sealed.len() != stub_padded.len() || auth_value.len() != auth_value_len {
            return Err(RpcError::Protocol(
                "Kerberos sealer returned unexpected output lengths".into(),
            ));
        }
        req[STUB_OFF..STUB_OFF + stub_padded.len()].copy_from_slice(&sealed);
        req[n - auth_value_len..].copy_from_slice(&auth_value);
        let mut budget = ResponseBudget::new(self.limits);
        self.send_until(&req, budget.deadline).await?;
        let mut plain = Vec::new();
        loop {
            let resp = self.recv_until(budget.deadline).await?;
            let parsed = pdu::parse_sealed_response_fragment(
                &resp,
                call_id,
                STUB_OFF,
                pdu::RPC_C_AUTHN_GSS_KERBEROS,
                auth_value_len,
            )?;
            budget.observe(parsed.frag_length, parsed.pfc_flags)?;
            // Short-circuit fault PDUs that arrived without any sealed payload — no
            // ciphertext to unseal. See `parse_sealed_response_any`: a FAULT with
            // auth_length=0 is legitimate (Server 2019+ Task Scheduler emits it on
            // SchRpcRegisterTask errors).
            if let Some(status) = parsed.fault_status {
                if parsed.auth_value.is_empty() && parsed.sealed_stub.is_empty() {
                    return Err(RpcError::Fault(status));
                }
            }
            let sealer = self
                .krb_seal
                .as_mut()
                .ok_or_else(|| RpcError::Protocol("session not kerberos-sealed".into()))?;
            let mut chunk = sealer.unseal_pdu(
                parsed.signed_pdu,
                parsed.stub_start,
                parsed.sealed_stub.len(),
                parsed.auth_value,
            )?;
            let plain_len = chunk
                .len()
                .checked_sub(parsed.pad_len as usize)
                .ok_or_else(|| RpcError::Protocol("Kerberos plaintext shorter than pad".into()))?;
            chunk.truncate(plain_len);
            if let Some(status) = parsed.fault_status {
                return Err(RpcError::Fault(status));
            }
            plain.extend_from_slice(&chunk);
            if parsed.pfc_flags & pdu::PFC_LAST_FRAG != 0 {
                return Ok(plain);
            }
        }
    }

    /// Issue a sign+sealed request over an authenticated ([`bind_sealed`](Self::bind_sealed))
    /// session. The MAC covers the whole PDU minus the trailing 16-byte signature (over the
    /// plaintext stub); only the stub is encrypted. The response is verified and decrypted.
    pub async fn call_sealed(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        const STUB_OFF: usize = 24; // header(16) + alloc_hint(4) + cont_id(2) + opnum(2)
        let pad_len = ((4 - (stub.len() % 4)) % 4) as u8;
        let mut stub_padded = stub.to_vec();
        stub_padded.extend(std::iter::repeat(0u8).take(pad_len as usize));

        // Assemble the PDU with a plaintext stub and a zeroed signature, then MAC the whole
        // thing (minus the signature) and encrypt the stub in place.
        let call_id = self.next_call_id();
        let alloc_hint = u32::try_from(stub.len())
            .map_err(|_| RpcError::Protocol("request stub exceeds u32 alloc_hint".into()))?;
        let mut req = pdu::try_build_request_sealed(
            call_id,
            0,
            opnum,
            &stub_padded,
            pad_len,
            &[0u8; 16],
            alloc_hint,
        )?;
        self.ensure_request_fits(req.len())?;
        let n = req.len();
        let sign_over = req[..n - 16].to_vec();
        let seal = self
            .seal
            .as_mut()
            .ok_or_else(|| RpcError::Protocol("session not sealed".into()))?;
        let (sealed, signature) = seal.seal_pdu(&sign_over, &stub_padded);
        if sealed.len() != stub_padded.len() || signature.len() != 16 {
            return Err(RpcError::Protocol(
                "NTLM sealer returned unexpected output lengths".into(),
            ));
        }
        req[STUB_OFF..STUB_OFF + stub_padded.len()].copy_from_slice(&sealed);
        req[n - 16..].copy_from_slice(&signature);
        // A large object (e.g. DCSync of a DC/computer) spans multiple sealed RESPONSE fragments.
        // Each fragment is independently RC4-sealed and HMAC-signed with the incrementing receive
        // sequence; the RC4 keystream is continuous, so unseal each in order and concatenate the
        // plaintext stubs until PFC_LAST_FRAG.
        let mut budget = ResponseBudget::new(self.limits);
        self.send_until(&req, budget.deadline).await?;
        let mut plain = Vec::new();
        loop {
            let resp = self.recv_until(budget.deadline).await?;
            let parsed = pdu::parse_sealed_response_fragment(
                &resp,
                call_id,
                STUB_OFF,
                pdu::RPC_C_AUTHN_WINNT,
                16,
            )?;
            budget.observe(parsed.frag_length, parsed.pfc_flags)?;
            let seal = self
                .seal
                .as_mut()
                .ok_or_else(|| RpcError::Protocol("session not sealed".into()))?;
            let mut chunk = seal
                .unseal_pdu(
                    parsed.signed_pdu,
                    parsed.stub_start,
                    parsed.sealed_stub.len(),
                    parsed.auth_value,
                )
                .map_err(|e| RpcError::Protocol(format!("unseal response: {e}")))?;
            let plain_len = chunk
                .len()
                .checked_sub(parsed.pad_len as usize)
                .ok_or_else(|| RpcError::Protocol("NTLM plaintext shorter than pad".into()))?;
            chunk.truncate(plain_len);
            if let Some(status) = parsed.fault_status {
                return Err(RpcError::Fault(status));
            }
            plain.extend_from_slice(&chunk);
            if parsed.pfc_flags & pdu::PFC_LAST_FRAG != 0 {
                return Ok(plain);
            }
        }
    }

    /// An ORPC (DCOM object) sealed request: like [`call_sealed`](Self::call_sealed) but carries the
    /// target object's IPID as the PDU object UUID (stub offset 40). Used for method calls on an
    /// activated DCOM interface (IWbemLevel1Login, IWbemServices …).
    pub async fn call_sealed_object(
        &mut self,
        opnum: u16,
        object: &[u8; 16],
        stub: &[u8],
    ) -> Result<Vec<u8>> {
        const STUB_OFF: usize = 40; // header(16)+alloc(4)+cont(2)+opnum(2)+object(16)
        let pad_len = ((4 - (stub.len() % 4)) % 4) as u8;
        let mut stub_padded = stub.to_vec();
        stub_padded.extend(std::iter::repeat(0u8).take(pad_len as usize));

        let call_id = self.next_call_id();
        let alloc_hint = u32::try_from(stub.len())
            .map_err(|_| RpcError::Protocol("request stub exceeds u32 alloc_hint".into()))?;
        let mut req = pdu::try_build_request_sealed_object(
            call_id,
            0,
            opnum,
            object,
            &stub_padded,
            pad_len,
            &[0u8; 16],
            alloc_hint,
        )?;
        self.ensure_request_fits(req.len())?;
        let n = req.len();
        let sign_over = req[..n - 16].to_vec();
        let seal = self
            .seal
            .as_mut()
            .ok_or_else(|| RpcError::Protocol("session not sealed".into()))?;
        let (sealed, signature) = seal.seal_pdu(&sign_over, &stub_padded);
        if sealed.len() != stub_padded.len() || signature.len() != 16 {
            return Err(RpcError::Protocol(
                "NTLM sealer returned unexpected output lengths".into(),
            ));
        }
        req[STUB_OFF..STUB_OFF + stub_padded.len()].copy_from_slice(&sealed);
        req[n - 16..].copy_from_slice(&signature);
        // RESPONSE PDUs carry no object UUID — their stub begins at 24 (header 16 + alloc_hint 4 +
        // p_cont_id 2 + cancel_count 1 + reserved 1), unlike the request's 40.
        const RESP_STUB_OFF: usize = 24;
        let mut budget = ResponseBudget::new(self.limits);
        self.send_until(&req, budget.deadline).await?;
        let mut plain = Vec::new();
        loop {
            let resp = self.recv_until(budget.deadline).await?;
            let parsed = pdu::parse_sealed_response_fragment(
                &resp,
                call_id,
                RESP_STUB_OFF,
                pdu::RPC_C_AUTHN_WINNT,
                16,
            )?;
            budget.observe(parsed.frag_length, parsed.pfc_flags)?;
            let seal = self
                .seal
                .as_mut()
                .ok_or_else(|| RpcError::Protocol("session not sealed".into()))?;
            let mut chunk = seal
                .unseal_pdu(
                    parsed.signed_pdu,
                    parsed.stub_start,
                    parsed.sealed_stub.len(),
                    parsed.auth_value,
                )
                .map_err(|e| RpcError::Protocol(format!("unseal response: {e}")))?;
            let plain_len = chunk
                .len()
                .checked_sub(parsed.pad_len as usize)
                .ok_or_else(|| RpcError::Protocol("NTLM plaintext shorter than pad".into()))?;
            chunk.truncate(plain_len);
            if let Some(status) = parsed.fault_status {
                return Err(RpcError::Fault(status));
            }
            plain.extend_from_slice(&chunk);
            if parsed.pfc_flags & pdu::PFC_LAST_FRAG != 0 {
                return Ok(plain);
            }
        }
    }
}

/// DCE/RPC over an SMB2 named pipe: each bind/request is one FSCTL_PIPE_TRANSCEIVE.
/// Borrows an authenticated, tree-connected `SmbClient` and an open pipe FileId.
pub struct SmbPipe<'a> {
    client: &'a mut smb2_client::SmbClient,
    file_id: [u8; 16],
    call_id: u32,
    seal: Option<SealState>,
    /// Kerberos sealer (mutually exclusive with `seal`): set when the pipe was
    /// bound via `bind_sealed_kerberos`; owns the trait object so the concrete
    /// crypto impl (e.g. adhammer-kerberos's AES256-CTS-HMAC-SHA1-96 sealer)
    /// stays outside this crate.
    krb_seal: Option<Box<dyn crate::krb_seal::KrbSealer + Send>>,
    limits: TransportLimits,
    max_request_frag: usize,
}

impl<'a> SmbPipe<'a> {
    pub fn new(client: &'a mut smb2_client::SmbClient, file_id: [u8; 16]) -> Self {
        Self::new_with_limits(client, file_id, TransportLimits::default())
    }

    /// Construct a named-pipe transport with explicit availability limits.
    pub fn new_with_limits(
        client: &'a mut smb2_client::SmbClient,
        file_id: [u8; 16],
        limits: TransportLimits,
    ) -> Self {
        SmbPipe {
            client,
            file_id,
            call_id: 1,
            seal: None,
            krb_seal: None,
            limits,
            max_request_frag: 5840,
        }
    }

    /// Replace limits for subsequent calls on this pipe.
    pub fn set_limits(&mut self, limits: TransportLimits) {
        self.limits = limits;
    }

    async fn transact(&mut self, pdu_bytes: &[u8]) -> Result<Vec<u8>> {
        self.transact_until(pdu_bytes, Instant::now() + self.limits.io_timeout)
            .await
    }

    async fn transact_until(
        &mut self,
        pdu_bytes: &[u8],
        call_deadline: Instant,
    ) -> Result<Vec<u8>> {
        timeout_at(
            bounded_deadline(call_deadline, self.limits.io_timeout),
            self.client.transact(&self.file_id, pdu_bytes),
        )
        .await
        .map_err(|_| timeout_error("SMB pipe transact"))?
        .map_err(|e| RpcError::Protocol(format!("smb transact: {e}")))
    }

    async fn read_pipe_until(&mut self, call_deadline: Instant) -> Result<Vec<u8>> {
        timeout_at(
            bounded_deadline(call_deadline, self.limits.io_timeout),
            self.client.read_pipe(&self.file_id, 0x0001_0000),
        )
        .await
        .map_err(|_| timeout_error("SMB pipe read"))?
        .map_err(|e| RpcError::Protocol(format!("pipe read: {e}")))
    }

    async fn write_pipe(&mut self, bytes: &[u8], operation: &str) -> Result<()> {
        self.write_pipe_until(bytes, operation, Instant::now() + self.limits.io_timeout)
            .await
    }

    async fn write_pipe_until(
        &mut self,
        bytes: &[u8],
        operation: &str,
        call_deadline: Instant,
    ) -> Result<()> {
        timeout_at(
            bounded_deadline(call_deadline, self.limits.io_timeout),
            self.client.write_pipe(&self.file_id, bytes),
        )
        .await
        .map_err(|_| timeout_error(operation))?
        .map_err(|e| RpcError::Protocol(format!("{operation}: {e}")))?;
        Ok(())
    }

    fn next_call_id(&mut self) -> u32 {
        let id = self.call_id;
        self.call_id = self.call_id.wrapping_add(1);
        id
    }

    fn accept_bind_ack(&mut self, buf: &[u8], call_id: u32) -> Result<()> {
        let ack = pdu::parse_bind_ack(buf, Some(call_id))?;
        self.max_request_frag = ack.max_recv_frag as usize;
        Ok(())
    }

    fn ensure_request_fits(&self, request_len: usize) -> Result<()> {
        if request_len > self.max_request_frag {
            return Err(RpcError::Protocol(format!(
                "request PDU is {request_len} bytes, exceeding negotiated max_recv_frag {}; request fragmentation is required",
                self.max_request_frag
            )));
        }
        Ok(())
    }

    async fn collect_plain_response(
        &mut self,
        mut raw: Vec<u8>,
        call_id: u32,
        mut budget: ResponseBudget,
    ) -> Result<Vec<u8>> {
        let mut plain = Vec::new();
        loop {
            budget.ensure_buffered(raw.len())?;
            while raw.len() >= 16 {
                let h = pdu::parse_header(&raw)?;
                let frag = h.frag_length as usize;
                if frag < 16 {
                    return Err(RpcError::Protocol(format!("frag_length {frag} < 16")));
                }
                if raw.len() < frag {
                    break;
                }
                let parsed = pdu::parse_plain_response_fragment(&raw[..frag], Some(call_id))?;
                budget.observe(parsed.frag_length, parsed.pfc_flags)?;
                plain.extend_from_slice(parsed.stub);
                let is_last = parsed.pfc_flags & pdu::PFC_LAST_FRAG != 0;
                raw.drain(..frag);
                if is_last {
                    if !raw.is_empty() {
                        return Err(RpcError::Protocol(
                            "unexpected bytes after final response fragment".into(),
                        ));
                    }
                    return Ok(plain);
                }
            }
            let more = self.read_pipe_until(budget.deadline).await?;
            if more.is_empty() {
                return Err(RpcError::Protocol(
                    "SMB pipe ended before PFC_LAST_FRAG".into(),
                ));
            }
            budget.ensure_buffered(raw.len().saturating_add(more.len()))?;
            raw.extend_from_slice(&more);
        }
    }

    pub async fn bind(&mut self, syntax: Syntax) -> Result<()> {
        let call_id = self.next_call_id();
        let bind = pdu::try_build_bind(call_id, syntax)?;
        let resp = self.transact(&bind).await?;
        self.accept_bind_ack(&resp, call_id)?;
        pdu::reject_bind_ack_auth(&resp)
    }

    pub async fn call(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        let call_id = self.next_call_id();
        let mut requests =
            pdu::try_build_request_fragments(call_id, 0, opnum, stub, self.max_request_frag)?;
        let last = requests
            .pop()
            .ok_or_else(|| RpcError::Protocol("request builder produced no fragments".into()))?;
        let budget = ResponseBudget::new(self.limits);
        for request in requests {
            self.write_pipe_until(&request, "fragmented RPC request write", budget.deadline)
                .await?;
        }
        let raw = self.transact_until(&last, budget.deadline).await?;
        self.collect_plain_response(raw, call_id, budget).await
    }

    /// Bind with NTLMSSP sign+seal (RPC packet privacy) over the pipe — required by interfaces
    /// that reject plaintext RPC (Task Scheduler, the CA's ICertPassage, …). The BIND rides a
    /// transceive; the unacknowledged AUTH3 is a fire-and-forget pipe WRITE.
    pub async fn bind_sealed(
        &mut self,
        syntax: Syntax,
        domain: &str,
        user: &str,
        password: &str,
        workstation: &str,
    ) -> Result<()> {
        let ntlm = Ntlm::new_sealed();
        let bind_call_id = self.next_call_id();
        let bind = pdu::try_build_bind_auth(bind_call_id, syntax, ntlm.negotiate())?;
        let ack = self.transact(&bind).await?;
        self.accept_bind_ack(&ack, bind_call_id)?;
        let challenge = pdu::bind_ack_auth_value(
            &ack,
            pdu::RPC_C_AUTHN_WINNT,
            pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            true,
        )?
        .ok_or_else(|| RpcError::Protocol("NTLM BIND_ACK verifier disappeared".into()))?;
        let (type3, exported) = ntlm
            .authenticate(&challenge, domain, user, password, workstation)
            .map_err(|e| RpcError::Protocol(format!("ntlm authenticate: {e}")))?;
        let auth3 = pdu::try_build_auth3(bind_call_id, &type3)?;
        self.write_pipe(&auth3, "AUTH3 write").await?;
        self.seal = Some(SealState::new(&exported));
        Ok(())
    }

    /// Like [`bind_sealed`](Self::bind_sealed) but pass-the-hash: authenticate
    /// with a raw NT hash instead of a plaintext password.
    ///
    /// Use when the SMB session was opened with `SmbClient::login_hash` so that
    /// the RPC sign+seal BIND also uses the hash — not an empty password that
    /// the server rejects with `RPC fault 0x00000005`.
    pub async fn bind_sealed_hash(
        &mut self,
        syntax: Syntax,
        domain: &str,
        user: &str,
        nt_hash: &[u8; 16],
        workstation: &str,
    ) -> Result<()> {
        let ntlm = Ntlm::new_sealed();
        let bind_call_id = self.next_call_id();
        let bind = pdu::try_build_bind_auth(bind_call_id, syntax, ntlm.negotiate())?;
        let ack = self.transact(&bind).await?;
        self.accept_bind_ack(&ack, bind_call_id)?;
        let challenge = pdu::bind_ack_auth_value(
            &ack,
            pdu::RPC_C_AUTHN_WINNT,
            pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            true,
        )?
        .ok_or_else(|| RpcError::Protocol("NTLM BIND_ACK verifier disappeared".into()))?;
        let (type3, exported) = ntlm
            .authenticate_hash(&challenge, domain, user, nt_hash, workstation)
            .map_err(|e| RpcError::Protocol(format!("ntlm authenticate (hash): {e}")))?;
        let auth3 = pdu::try_build_auth3(bind_call_id, &type3)?;
        self.write_pipe(&auth3, "AUTH3 write").await?;
        self.seal = Some(SealState::new(&exported));
        Ok(())
    }

    /// Kerberos sign+seal BIND (auth_type = GSS_KERBEROS, auth_level = PKT_PRIVACY).
    /// The `ap_req_gss_token` is a GSS-API `InitialContextToken(SPNEGO → krb5(AP-REQ))` built
    /// by a Kerberos crate (e.g. adhammer-kerberos's `build_ap_req_gss`); `sealer` is the
    /// concrete `KrbSealer` impl that already holds the same session key the AP-REQ was
    /// built with. The AP-REQ here has mutual-required OFF, so the ack carries no AP-REP
    /// and AUTH3 is empty — kept present because Windows expects a close-of-negotiation PDU.
    pub async fn bind_sealed_kerberos(
        &mut self,
        syntax: Syntax,
        ap_req_gss_token: &[u8],
        sealer: Box<dyn crate::krb_seal::KrbSealer + Send>,
    ) -> Result<()> {
        let bind_call_id = self.next_call_id();
        let bind = pdu::try_build_bind_auth_kerberos(
            bind_call_id,
            syntax,
            ap_req_gss_token,
            pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        )?;
        let ack = self.transact(&bind).await?;
        self.accept_bind_ack(&ack, bind_call_id)?;
        // For non-mutual (ap_options=0) the ack has no verifier — extract is best-effort.
        // If a caller uses mutual-required they should verify the AP-REP separately before
        // trusting the sealer's server_seq; this scaffolding is minimum-mutual.
        pdu::bind_ack_auth_value(
            &ack,
            pdu::RPC_C_AUTHN_GSS_KERBEROS,
            pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            false,
        )?;
        let auth3 =
            pdu::try_build_auth3_kerberos(bind_call_id, &[], pdu::RPC_C_AUTHN_LEVEL_PKT_PRIVACY)?;
        self.write_pipe(&auth3, "AUTH3 write").await?;
        self.krb_seal = Some(sealer);
        Ok(())
    }

    /// Sign+sealed request over a Kerberos-bound pipe. Uses `build_request_sealed_krb` with
    /// the sealer's auth_value length (varies per Kerberos etype — 28 for AES256-CTS-HMAC-SHA1-96
    /// under the current dcerpc contract). Mirrors [`call_sealed`](Self::call_sealed).
    pub async fn call_sealed_kerberos(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        const STUB_OFF: usize = 24;
        let pad_len = ((4 - (stub.len() % 4)) % 4) as u8;
        let mut stub_padded = stub.to_vec();
        stub_padded.extend(std::iter::repeat(0u8).take(pad_len as usize));

        let auth_value_len = self
            .krb_seal
            .as_ref()
            .ok_or_else(|| RpcError::Protocol("pipe not kerberos-sealed".into()))?
            .auth_value_len();

        let call_id = self.next_call_id();
        let alloc_hint = u32::try_from(stub.len())
            .map_err(|_| RpcError::Protocol("request stub exceeds u32 alloc_hint".into()))?;
        let placeholder_av = vec![0u8; auth_value_len];
        let mut req = pdu::try_build_request_sealed_krb(
            call_id,
            0,
            opnum,
            &stub_padded,
            pad_len,
            &placeholder_av,
            alloc_hint,
        )?;
        self.ensure_request_fits(req.len())?;
        let n = req.len();
        let sign_over = req[..n - auth_value_len].to_vec();
        let sealer = self
            .krb_seal
            .as_mut()
            .ok_or_else(|| RpcError::Protocol("pipe not kerberos-sealed".into()))?;
        let (sealed, auth_value) = sealer.seal_pdu(&sign_over, &stub_padded);
        if sealed.len() != stub_padded.len() || auth_value.len() != auth_value_len {
            return Err(RpcError::Protocol(
                "Kerberos sealer returned unexpected output lengths".into(),
            ));
        }
        req[STUB_OFF..STUB_OFF + stub_padded.len()].copy_from_slice(&sealed);
        req[n - auth_value_len..].copy_from_slice(&auth_value);

        let mut budget = ResponseBudget::new(self.limits);
        let mut raw = self.transact_until(&req, budget.deadline).await?;
        let mut plain = Vec::new();
        loop {
            budget.ensure_buffered(raw.len())?;
            while raw.len() >= 16 {
                let h = pdu::parse_header(&raw)?;
                let frag = h.frag_length as usize;
                if frag < 16 {
                    return Err(RpcError::Protocol(format!("frag_length {frag} < 16")));
                }
                if raw.len() < frag {
                    break;
                }
                let parsed = pdu::parse_sealed_response_fragment(
                    &raw[..frag],
                    call_id,
                    STUB_OFF,
                    pdu::RPC_C_AUTHN_GSS_KERBEROS,
                    auth_value_len,
                )?;
                budget.observe(parsed.frag_length, parsed.pfc_flags)?;
                let sealer = self
                    .krb_seal
                    .as_mut()
                    .ok_or_else(|| RpcError::Protocol("pipe not kerberos-sealed".into()))?;
                let mut chunk = sealer.unseal_pdu(
                    parsed.signed_pdu,
                    parsed.stub_start,
                    parsed.sealed_stub.len(),
                    parsed.auth_value,
                )?;
                let plain_len = chunk
                    .len()
                    .checked_sub(parsed.pad_len as usize)
                    .ok_or_else(|| {
                        RpcError::Protocol("Kerberos plaintext shorter than pad".into())
                    })?;
                chunk.truncate(plain_len);
                if let Some(status) = parsed.fault_status {
                    return Err(RpcError::Fault(status));
                }
                plain.extend_from_slice(&chunk);
                let is_last = parsed.pfc_flags & pdu::PFC_LAST_FRAG != 0;
                raw.drain(..frag);
                if is_last {
                    if !raw.is_empty() {
                        return Err(RpcError::Protocol(
                            "unexpected bytes after final response fragment".into(),
                        ));
                    }
                    return Ok(plain);
                }
            }
            let more = self.read_pipe_until(budget.deadline).await?;
            if more.is_empty() {
                return Err(RpcError::Protocol(
                    "SMB pipe ended before PFC_LAST_FRAG".into(),
                ));
            }
            budget.ensure_buffered(raw.len().saturating_add(more.len()))?;
            raw.extend_from_slice(&more);
        }
    }

    /// Sign+sealed request over the pipe with bounded multi-fragment response reassembly.
    /// Mirrors [`RpcTcp::call_sealed`].
    pub async fn call_sealed(&mut self, opnum: u16, stub: &[u8]) -> Result<Vec<u8>> {
        const STUB_OFF: usize = 24;
        let pad_len = ((4 - (stub.len() % 4)) % 4) as u8;
        let mut stub_padded = stub.to_vec();
        stub_padded.extend(std::iter::repeat(0u8).take(pad_len as usize));
        let call_id = self.next_call_id();
        let alloc_hint = u32::try_from(stub.len())
            .map_err(|_| RpcError::Protocol("request stub exceeds u32 alloc_hint".into()))?;
        let mut req = pdu::try_build_request_sealed(
            call_id,
            0,
            opnum,
            &stub_padded,
            pad_len,
            &[0u8; 16],
            alloc_hint,
        )?;
        self.ensure_request_fits(req.len())?;
        let n = req.len();
        let sign_over = req[..n - 16].to_vec();
        let seal = self
            .seal
            .as_mut()
            .ok_or_else(|| RpcError::Protocol("pipe not sealed".into()))?;
        let (sealed, signature) = seal.seal_pdu(&sign_over, &stub_padded);
        if sealed.len() != stub_padded.len() || signature.len() != 16 {
            return Err(RpcError::Protocol(
                "NTLM sealer returned unexpected output lengths".into(),
            ));
        }
        req[STUB_OFF..STUB_OFF + stub_padded.len()].copy_from_slice(&sealed);
        req[n - 16..].copy_from_slice(&signature);
        // A large reply (e.g. an issued certificate) spans several sealed RESPONSE fragments.
        // The first arrives in the transceive output; the rest must be drained from the pipe
        // with SMB READs. Unseal each fragment exactly once (the receive keystream + sequence
        // advance per fragment) as it becomes complete, until PFC_LAST_FRAG.
        let mut budget = ResponseBudget::new(self.limits);
        let mut raw = self.transact_until(&req, budget.deadline).await?;
        let mut plain = Vec::new();
        loop {
            budget.ensure_buffered(raw.len())?;
            while raw.len() >= 16 {
                let h = pdu::parse_header(&raw)?;
                let frag = h.frag_length as usize;
                if frag < 16 {
                    return Err(RpcError::Protocol(format!("frag_length {frag} < 16")));
                }
                if raw.len() < frag {
                    break;
                }
                let parsed = pdu::parse_sealed_response_fragment(
                    &raw[..frag],
                    call_id,
                    STUB_OFF,
                    pdu::RPC_C_AUTHN_WINNT,
                    16,
                )?;
                budget.observe(parsed.frag_length, parsed.pfc_flags)?;
                let seal = self
                    .seal
                    .as_mut()
                    .ok_or_else(|| RpcError::Protocol("pipe not sealed".into()))?;
                let mut chunk = seal
                    .unseal_pdu(
                        parsed.signed_pdu,
                        parsed.stub_start,
                        parsed.sealed_stub.len(),
                        parsed.auth_value,
                    )
                    .map_err(|e| RpcError::Protocol(format!("unseal response: {e}")))?;
                let plain_len = chunk
                    .len()
                    .checked_sub(parsed.pad_len as usize)
                    .ok_or_else(|| RpcError::Protocol("NTLM plaintext shorter than pad".into()))?;
                chunk.truncate(plain_len);
                if let Some(status) = parsed.fault_status {
                    return Err(RpcError::Fault(status));
                }
                plain.extend_from_slice(&chunk);
                let is_last = parsed.pfc_flags & pdu::PFC_LAST_FRAG != 0;
                raw.drain(..frag);
                if is_last {
                    if !raw.is_empty() {
                        return Err(RpcError::Protocol(
                            "unexpected bytes after final response fragment".into(),
                        ));
                    }
                    return Ok(plain);
                }
            }
            let more = self.read_pipe_until(budget.deadline).await?;
            if more.is_empty() {
                return Err(RpcError::Protocol(
                    "SMB pipe ended before PFC_LAST_FRAG".into(),
                ));
            }
            budget.ensure_buffered(raw.len().saturating_add(more.len()))?;
            raw.extend_from_slice(&more);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn response_budget_rejects_fragment_and_byte_exhaustion() {
        let limits = TransportLimits {
            max_response_bytes: 40,
            max_response_fragments: 1,
            ..TransportLimits::default()
        };
        let mut budget = ResponseBudget::new(limits);
        assert!(budget.observe(24, pdu::PFC_FIRST_FRAG).is_ok());
        assert!(budget.observe(16, pdu::PFC_LAST_FRAG).is_err());

        let mut budget = ResponseBudget::new(TransportLimits {
            max_response_bytes: 23,
            ..TransportLimits::default()
        });
        assert!(budget
            .observe(24, pdu::PFC_FIRST_FRAG | pdu::PFC_LAST_FRAG)
            .is_err());
    }

    #[tokio::test]
    async fn tcp_receive_times_out_against_silent_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let mut rpc = RpcTcp {
            stream,
            call_id: 1,
            seal: None,
            session_key: None,
            pending_relay_bind: None,
            krb_seal: None,
            limits: TransportLimits {
                io_timeout: Duration::from_millis(25),
                ..TransportLimits::default()
            },
            max_request_frag: 5840,
        };

        let error = rpc.recv().await.unwrap_err();
        assert!(matches!(error, RpcError::Io(ref e) if e.kind() == std::io::ErrorKind::TimedOut));
        peer.abort();
    }
}
