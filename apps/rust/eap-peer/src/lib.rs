//! Experimental EAP-MD5 peer. Wired AutoConfig owns Ethernet transport.
use anyhow::{Result, ensure};
use netauth::protocol::{MAX_FRAME, gbk, md5_response};
use serde::{Deserialize, Serialize};

#[cfg(windows)]
mod windows;

// RFC 5612's example enterprise number, for local evaluation only.
pub const AUTHOR_ID: u32 = 32473;
pub const CONNECTION_DATA: &[u8] = b"SYSU-EAP-MD5-v1";

#[derive(Deserialize, Serialize)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn new(username: String, password: String) -> Result<Self> {
        let credentials = Self { username, password };
        credentials.validate()?;
        Ok(credentials)
    }

    fn validate(&self) -> Result<()> {
        // EAPHost constructs the outer identity from UTF-16. NetIDs are ASCII;
        // restricting them avoids disagreeing with our GBK method identity.
        ensure!(
            !self.username.is_empty()
                && self.username.len() <= 512
                && self.username.bytes().all(|c| c.is_ascii_graphic()),
            "NetID must contain 1–512 printable ASCII characters"
        );
        ensure!(
            !self.password.is_empty() && self.password.len() <= 1024,
            "invalid password length"
        );
        let mut encoded = gbk(&self.password)?;
        wipe(&mut encoded);
        Ok(())
    }
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // Prevent the compiler from eliminating the credential erasure.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

impl Drop for Credentials {
    fn drop(&mut self) {
        // No string operations follow these writes; zero is valid UTF-8.
        unsafe { wipe(self.password.as_bytes_mut()) };
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Discard,
    Send,
    Result,
}

pub struct Peer {
    username: Vec<u8>,
    password: Vec<u8>,
    max_packet: usize,
    response: Vec<u8>,
    challenge_id: Option<u8>,
    success: bool,
    failed: bool,
}

impl Peer {
    pub fn new(credentials: Credentials, max_packet: usize) -> Result<Self> {
        credentials.validate()?;
        ensure!(
            max_packet >= 22 + credentials.username.len(),
            "EAP packet limit too small"
        );
        Ok(Self {
            username: gbk(&credentials.username)?,
            password: gbk(&credentials.password)?,
            max_packet: max_packet.min(MAX_FRAME - 18),
            response: Vec::new(),
            challenge_id: None,
            success: false,
            failed: false,
        })
    }

    /// Process an EAP packet, without an Ethernet or EAPOL header.
    pub fn process(&mut self, packet: &[u8]) -> Action {
        self.response.clear();
        if packet.len() < 4 || packet.len() > MAX_FRAME - 18 {
            return Action::Discard;
        }
        let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
        if len != packet.len() {
            return Action::Discard;
        }
        let id = packet[1];
        match packet[0] {
            1 if packet.len() >= 5 && !self.failed => {
                let body = match packet[4] {
                    1 => self.username.clone(),
                    4 => match md5_response(id, &packet[5..], &self.username, &self.password) {
                        Ok(body) => body,
                        Err(_) => return Action::Discard,
                    },
                    _ => return Action::Discard,
                };
                let response_len = 5 + body.len();
                if response_len > self.max_packet {
                    return Action::Discard;
                }
                self.response.extend_from_slice(&[2, id]);
                self.response
                    .extend_from_slice(&(response_len as u16).to_be_bytes());
                self.response.push(packet[4]);
                self.response.extend_from_slice(&body);
                if packet[4] == 4 {
                    self.challenge_id = Some(id);
                    self.success = false;
                }
                Action::Send
            }
            3 | 4 if len == 4 && self.challenge_id == Some(id) => {
                self.failed = packet[0] == 4;
                self.success = !self.failed;
                Action::Result
            }
            _ => Action::Discard,
        }
    }

    pub fn response(&self) -> &[u8] {
        &self.response
    }

    /// EAPHost normally consumes Success/Failure and reports them separately.
    pub fn result(&self, host_success: bool) -> bool {
        !self.failed && self.challenge_id.is_some() && (self.success || host_success)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        wipe(&mut self.password);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netauth::protocol::{self, Packet};

    fn peer() -> Peer {
        Peer::new(
            Credentials::new("netid".into(), "密码".into()).unwrap(),
            1500,
        )
        .unwrap()
    }

    fn challenge(id: u8) -> Vec<u8> {
        let mut p = vec![1, id, 0, 22, 4, 16];
        p.extend(0..16);
        p
    }

    #[test]
    fn matches_existing_ethernet_md5_and_gbk_credentials() {
        let mut peer = peer();
        let request = challenge(7);
        assert_eq!(peer.process(&request), Action::Send);
        let frame = protocol::answer(
            [0; 6],
            [2; 6],
            &Packet {
                source: [2; 6],
                destination: [0; 6],
                code: 1,
                id: 7,
                kind: Some(4),
                data: &request[5..],
            },
            b"netid",
            &gbk("密码").unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(peer.response(), &frame[18..]);
        // Fixed digest fixture also guards against both backends sharing a bug.
        assert_eq!(
            &peer.response()[6..22],
            &[
                0x9c, 0xc1, 0x1d, 0x1f, 0xe7, 0xfd, 0x61, 0xac, 0x0f, 0xb8, 0x2b, 0x25, 0xbe, 0xb2,
                0xcc, 0xe9
            ]
        );
    }

    #[test]
    fn identity_and_repeated_challenges_need_no_terminal_success() {
        let mut peer = peer();
        assert_eq!(peer.process(&[1, 9, 0, 5, 1]), Action::Send);
        assert_eq!(peer.response(), b"\x02\x09\x00\x0a\x01netid");
        for id in [0, 7, 7, 255, 1] {
            assert_eq!(peer.process(&challenge(id)), Action::Send);
            assert_eq!(peer.response()[1], id);
        }
    }

    #[test]
    fn success_requires_challenge_and_failure_overrides_host_success() {
        let mut peer = peer();
        assert!(!peer.result(true));
        assert_eq!(peer.process(&[3, 1, 0, 4]), Action::Discard);
        peer.process(&challenge(1));
        assert!(!peer.result(false));
        assert!(peer.result(true));
        assert_eq!(peer.process(&[3, 2, 0, 4]), Action::Discard);
        assert_eq!(peer.process(&[3, 1, 0, 4]), Action::Result);
        assert!(peer.result(false));
        assert_eq!(peer.process(&[4, 1, 0, 4]), Action::Result);
        assert!(!peer.result(true));
        assert_eq!(peer.process(&challenge(2)), Action::Discard);
    }

    #[test]
    fn malformed_packets_cannot_reuse_response_or_authenticate() {
        let request = challenge(1);
        let mut peer = peer();
        for n in 0..request.len() {
            peer.process(&request);
            assert_eq!(peer.process(&request[..n]), Action::Discard);
            assert!(peer.response().is_empty());
        }
        for p in [&[1, 1, 0, 6, 4, 0][..], &[1, 1, 0, 5, 99], &[3, 1, 0, 5, 0]] {
            assert_eq!(peer.process(p), Action::Discard);
        }
    }

    #[test]
    fn credentials_and_transport_limits_are_checked() {
        for (u, p) in [
            ("", "p"),
            ("用户", "p"),
            ("a\0b", "p"),
            ("u", ""),
            ("u", "🔐"),
        ] {
            assert!(Credentials::new(u.into(), p.into()).is_err());
        }
        assert!(Peer::new(Credentials::new("u".into(), "p".into()).unwrap(), 22).is_err());
        let mut p = peer();
        assert_eq!(p.process(&vec![1; MAX_FRAME]), Action::Discard);
    }
}
