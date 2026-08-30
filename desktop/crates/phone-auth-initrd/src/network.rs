//! Minimal wired transport for early boot.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use phone_auth_protocol::SESSION_BINDING_LEN;
use phone_auth_session::framing::{read_frame, write_frame};
use phone_auth_session::{
    IdentityKey, PeerExpectation, PendingServerHandshake, SecureChannel, ServerBootstrap,
};
use phone_auth_verifier::session::{SecureSession, TransportSecurity};
use phone_auth_verifier::{random, verifier::now_ms};

/// Must match the paired phone's saved LAN transport name: it is part of the
/// session binding, not a cosmetic label.
pub const TRANSPORT_NAME: &str = "QrNetworkTransport";

pub struct WiredListener(TcpListener);

impl WiredListener {
    pub fn bind(port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))?;
        listener.set_nonblocking(true)?;
        Ok(Self(listener))
    }

    #[cfg(test)]
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    /// Accepts exactly one paired phone under one end-to-end timeout.
    pub fn accept(
        &self,
        identity: &IdentityKey,
        verifier_id: &str,
        phone_device_id: &str,
        phone_identity_spki: &[u8],
        timeout: Duration,
    ) -> io::Result<WiredSession> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "timeout is too large"))?;
        let (mut stream, peer) = loop {
            match self.0.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    let remaining = remaining(deadline)?;
                    thread::sleep(remaining.min(Duration::from_millis(10)));
                }
                Err(error) => return Err(error),
            }
        };
        stream.set_nonblocking(false)?;

        let lifetime_ms = remaining(deadline)?.as_millis().min(i64::MAX as u128) as i64;
        let bootstrap = ServerBootstrap::new(
            random::session_id(),
            verifier_id,
            "",
            identity,
            now_ms(),
            lifetime_ms.max(1),
        )
        .map_err(invalid_data)?;
        let (pending, hello) =
            PendingServerHandshake::begin(bootstrap, identity).map_err(invalid_data)?;
        let mut timed = DeadlineStream::new(&mut stream, deadline);
        write_frame(&mut timed, &hello)?;
        let answer = read_frame(&mut timed)?;
        let outcome = pending
            .finish(
                &answer,
                PeerExpectation::Paired {
                    device_id: phone_device_id,
                    identity_spki: phone_identity_spki,
                },
                TRANSPORT_NAME,
            )
            .map_err(invalid_data)?;

        Ok(WiredSession {
            channel: outcome.channel,
            stream,
            origin: format!("{TRANSPORT_NAME} • {peer}"),
            deadline,
            security: TransportSecurity {
                transport_name: TRANSPORT_NAME.into(),
                confidential: true,
                peer_authenticated: true,
                requires_network: true,
                proximity_signal: false,
                is_development: false,
            },
            closed: false,
        })
    }
}

pub struct WiredSession {
    channel: SecureChannel,
    stream: TcpStream,
    origin: String,
    deadline: Instant,
    security: TransportSecurity,
    closed: bool,
}

impl SecureSession for WiredSession {
    fn origin_label(&self) -> &str {
        &self.origin
    }

    fn session_binding(&self) -> [u8; SESSION_BINDING_LEN] {
        self.channel.session_binding()
    }

    fn security(&self) -> &TransportSecurity {
        &self.security
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        let record = self.channel.seal(frame).map_err(invalid_data)?;
        write_frame(
            &mut DeadlineStream::new(&mut self.stream, self.deadline),
            &record,
        )
    }

    fn receive(&mut self, timeout: Duration) -> io::Result<Vec<u8>> {
        if self.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        let requested = Instant::now()
            .checked_add(timeout)
            .unwrap_or(self.deadline)
            .min(self.deadline);
        let record = read_frame(&mut DeadlineStream::new(&mut self.stream, requested))?;
        self.channel.open(&record).map_err(invalid_data)
    }

    fn close(&mut self) -> io::Result<()> {
        self.closed = true;
        let _ = self.stream.shutdown(Shutdown::Both);
        Ok(())
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "initrd transport timed out",
        ))
    } else {
        Ok(remaining)
    }
}

struct DeadlineStream<'a> {
    stream: &'a mut TcpStream,
    deadline: Instant,
}

impl<'a> DeadlineStream<'a> {
    fn new(stream: &'a mut TcpStream, deadline: Instant) -> Self {
        Self { stream, deadline }
    }
}

impl Read for DeadlineStream<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.stream
            .set_read_timeout(Some(remaining(self.deadline)?))?;
        self.stream.read(buffer)
    }
}

impl Write for DeadlineStream<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream
            .set_write_timeout(Some(remaining(self.deadline)?))?;
        self.stream.flush()
    }
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use phone_auth_session::framing::{read_frame, write_frame};
    use phone_auth_session::{ClientHandshake, VerifierExpectation};

    #[test]
    fn a_real_tcp_handshake_only_accepts_the_paired_phone() {
        let server_identity = IdentityKey::generate();
        let server_spki = server_identity.public_key_spki().unwrap();
        let phone_identity = IdentityKey::generate();
        let phone_spki = phone_identity.public_key_spki().unwrap();
        let listener = WiredListener::bind(0).unwrap();
        let address =
            SocketAddr::from((Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port()));

        let phone = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            let hello = read_frame(&mut stream).unwrap();
            let (answer, mut outcome) = ClientHandshake::respond(
                &hello,
                VerifierExpectation::Paired {
                    identity_spki: &server_spki,
                },
                "phone-1",
                &phone_identity,
                TRANSPORT_NAME,
                now_ms(),
            )
            .unwrap();
            write_frame(&mut stream, &answer).unwrap();
            let response = outcome.channel.seal(b"wrapped-key").unwrap();
            write_frame(&mut stream, &response).unwrap();
            let request = read_frame(&mut stream).unwrap();
            assert_eq!(outcome.channel.open(&request).unwrap(), b"ack");
            outcome.channel.session_binding()
        });

        let mut session = listener
            .accept(
                &server_identity,
                "desktop-1",
                "phone-1",
                &phone_spki,
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(
            session.receive(Duration::from_secs(1)).unwrap(),
            b"wrapped-key"
        );
        session.send(b"ack").unwrap();
        assert_eq!(session.session_binding(), phone.join().unwrap());
    }

    #[test]
    fn no_phone_consumes_only_the_configured_timeout() {
        let listener = WiredListener::bind(0).unwrap();
        let started = Instant::now();
        let error = match listener.accept(
            &IdentityKey::generate(),
            "desktop-1",
            "phone-1",
            &[1; 91],
            Duration::from_millis(30),
        ) {
            Ok(_) => panic!("a listener with no phone must time out"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_phone_with_another_identity_is_refused() {
        let server_identity = IdentityKey::generate();
        let server_spki = server_identity.public_key_spki().unwrap();
        let paired_phone_spki = IdentityKey::generate().public_key_spki().unwrap();
        let impostor = IdentityKey::generate();
        let listener = WiredListener::bind(0).unwrap();
        let address =
            SocketAddr::from((Ipv4Addr::LOCALHOST, listener.local_addr().unwrap().port()));

        let client = thread::spawn(move || {
            let mut stream = TcpStream::connect(address).unwrap();
            let hello = read_frame(&mut stream).unwrap();
            let (answer, _) = ClientHandshake::respond(
                &hello,
                VerifierExpectation::Paired {
                    identity_spki: &server_spki,
                },
                "phone-1",
                &impostor,
                TRANSPORT_NAME,
                now_ms(),
            )
            .unwrap();
            write_frame(&mut stream, &answer).unwrap();
        });

        let error = match listener.accept(
            &server_identity,
            "desktop-1",
            "phone-1",
            &paired_phone_spki,
            Duration::from_secs(2),
        ) {
            Ok(_) => panic!("an unpaired identity must not establish a session"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        client.join().unwrap();
    }
}
