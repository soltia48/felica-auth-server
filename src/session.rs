//! Session management: the per-session worker thread and the [`SessionManager`].
//!
//! The server performs **mutual authentication only**. Once authentication
//! succeeds it hands the resulting ephemeral secure-session material (DES session
//! key, transaction ID and transaction counter) to the client and forgets the
//! session. The client then runs the encrypted Read/Write commands itself, so
//! card data never passes through the server; only the long-term system, area and
//! service keys stay here.
//!
//! Each session owns an OS worker thread that drives `felica-rs`'s high-level
//! `FelicaStandard::mutual_authentication` against a [`RelayDriver`]. Because that
//! single call spans two card round-trips — and therefore two HTTP requests — the
//! worker blocks inside the driver's `transceive` between requests. Coordination
//! uses three unbounded channels:
//!
//! - `control` (HTTP → worker): start a mutual authentication.
//! - `card` (HTTP → relay driver): a card response to feed the pending transceive.
//! - `out` (worker/driver → HTTP): the next frame to relay, or the final result.
//!
//! Every client request delivers exactly one input (a control command or a card
//! response) and consumes exactly one `Out`, so the streams stay in lock-step.
//! Per-session serialization is enforced by an async mutex; the handler side
//! tracks whether the worker is next expecting a control command or a card
//! response to route each request and reject out-of-order ones cleanly.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use felica_rs::felica_standard::{FelicaStandard, SecureSessionCredentialsRef, ServiceCode};
use serde_json::{json, Value};
use tokio::sync::Mutex as TokioMutex;

use crate::error::{map_felica_error, ProtocolError};
use crate::keystore::KeyStore;
use crate::policy::{check_service_list_shape, is_read_only_service};
use crate::relay_driver::{Out, RelayDriver, SecureSessionMaterial};

/// A request from an HTTP handler asking the worker to authenticate.
struct StartAuth {
    system_code: u16,
    areas: Vec<u16>,
    services: Vec<u16>,
}

/// What the worker is next expecting from the client.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// A new authentication request.
    Control,
    /// A card response feeding the pending transceive.
    Card,
}

struct SessionInner {
    expect: Expect,
    /// Number of command frames emitted since the current auth started
    /// (used to label `auth1` vs `auth2`).
    auth_frames: u8,
}

struct Session {
    idm: [u8; 8],
    pmm: [u8; 8],
    control_tx: flume::Sender<StartAuth>,
    card_tx: flume::Sender<Vec<u8>>,
    out_rx: flume::Receiver<Out>,
    inner: TokioMutex<SessionInner>,
    last_seen: StdMutex<Instant>,
}

/// Parsed input for `POST /mutual-authentication`.
#[derive(Debug, Default)]
pub struct MutualAuthInput {
    pub session_id: Option<String>,
    pub idm: Option<[u8; 8]>,
    pub pmm: Option<[u8; 8]>,
    pub system_code: Option<u16>,
    pub areas: Option<Vec<u16>>,
    pub services: Option<Vec<u16>>,
    pub card_response: Option<Vec<u8>>,
}

/// In-memory manager of in-flight authentication sessions.
pub struct SessionManager {
    sessions: StdMutex<HashMap<String, Arc<Session>>>,
    keystore: Arc<KeyStore>,
    /// When set, only read-only services may be authenticated (and areas not at
    /// all), so the card will refuse any Write in the resulting session.
    read_only_nodes: bool,
    ttl: Duration,
    max_sessions: usize,
}

impl SessionManager {
    pub fn new(
        keystore: Arc<KeyStore>,
        read_only_nodes: bool,
        ttl: Duration,
        max_sessions: usize,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions: StdMutex::new(HashMap::new()),
            keystore,
            read_only_nodes,
            ttl,
            max_sessions,
        })
    }

    /// Spawn the background task that reaps sessions abandoned mid-authentication.
    /// Must be called from within a Tokio runtime.
    pub fn spawn_reaper(self: Arc<Self>) {
        let ttl = self.ttl;
        let interval = (ttl / 2).max(Duration::from_secs(1));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let now = Instant::now();
                let mut sessions = self.sessions.lock().unwrap();
                let before = sessions.len();
                sessions.retain(|_, session| {
                    let last = *session.last_seen.lock().unwrap();
                    now.duration_since(last) < ttl
                });
                let reaped = before - sessions.len();
                if reaped > 0 {
                    tracing::debug!(reaped, live = sessions.len(), "reaped idle sessions");
                }
            }
        });
    }

    /// Number of authentications currently in flight (for diagnostics / health).
    pub fn live_sessions(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    fn get_session(&self, session_id: &str) -> Result<Arc<Session>, ProtocolError> {
        self.sessions
            .lock()
            .unwrap()
            .get(session_id)
            .cloned()
            .ok_or_else(|| ProtocolError::not_found("unknown session_id"))
    }

    fn remove_session(&self, session_id: &str) {
        self.sessions.lock().unwrap().remove(session_id);
    }

    fn get_or_create_session(
        &self,
        session_id: &Option<String>,
        idm: &Option<[u8; 8]>,
        pmm: &Option<[u8; 8]>,
    ) -> Result<(String, Arc<Session>, bool), ProtocolError> {
        if let Some(sid) = session_id {
            let session = self.get_session(sid)?;
            if let Some(idm) = idm {
                if *idm != session.idm {
                    return Err(ProtocolError::bad_request(
                        "idm does not match existing session",
                    ));
                }
            }
            if let Some(pmm) = pmm {
                if *pmm != session.pmm {
                    return Err(ProtocolError::bad_request(
                        "pmm does not match existing session",
                    ));
                }
            }
            return Ok((sid.clone(), session, false));
        }

        let idm = idm.ok_or_else(|| {
            ProtocolError::bad_request("idm and pmm are required to start a session")
        })?;
        let pmm = pmm.ok_or_else(|| {
            ProtocolError::bad_request("idm and pmm are required to start a session")
        })?;
        let (id, session) = self.create_session(idm, pmm)?;
        Ok((id, session, true))
    }

    fn create_session(
        &self,
        idm: [u8; 8],
        pmm: [u8; 8],
    ) -> Result<(String, Arc<Session>), ProtocolError> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= self.max_sessions {
            return Err(ProtocolError::new(503, "too many active sessions"));
        }

        let (control_tx, control_rx) = flume::unbounded::<StartAuth>();
        let (card_tx, card_rx) = flume::unbounded::<Vec<u8>>();
        let (out_tx, out_rx) = flume::unbounded::<Out>();
        let keystore = Arc::clone(&self.keystore);
        std::thread::Builder::new()
            .name("felica-session".into())
            .spawn(move || run_session(idm, pmm, keystore, control_rx, card_rx, out_tx))
            .map_err(|e| ProtocolError::internal(format!("failed to spawn session worker: {e}")))?;

        let session = Arc::new(Session {
            idm,
            pmm,
            control_tx,
            card_tx,
            out_rx,
            inner: TokioMutex::new(SessionInner {
                expect: Expect::Control,
                auth_frames: 0,
            }),
            last_seen: StdMutex::new(Instant::now()),
        });
        let id = new_session_id();
        sessions.insert(id.clone(), Arc::clone(&session));
        Ok((id, session))
    }

    /// Drive `POST /mutual-authentication`.
    pub async fn handle_mutual_authentication(
        &self,
        input: MutualAuthInput,
    ) -> Result<Value, ProtocolError> {
        let (session_id, session, created) =
            self.get_or_create_session(&input.session_id, &input.idm, &input.pmm)?;
        let mut inner = session.inner.lock().await;
        let starting = inner.expect == Expect::Control;

        let out = if starting {
            if input.card_response.is_some() {
                return Err(ProtocolError::bad_request(
                    "card_response not expected at start of authentication",
                ));
            }
            let system_code = input
                .system_code
                .ok_or_else(|| ProtocolError::bad_request("system_code is required"))?;
            // FeliCa authentication needs at least one real area node.
            let areas = require_nonempty(input.areas, "areas")?;
            let services = require_nonempty(input.services, "services")?;
            if self.read_only_nodes {
                if let Err(err) = enforce_read_only_nodes(&services) {
                    if created {
                        self.remove_session(&session_id);
                    }
                    return Err(err);
                }
            }
            inner.auth_frames = 0;
            session
                .control_tx
                .send(StartAuth {
                    system_code,
                    areas,
                    services,
                })
                .map_err(|_| ProtocolError::internal("session worker unavailable"))?;
            recv_out(&session).await?
        } else {
            let card = input.card_response.ok_or_else(|| {
                ProtocolError::bad_request("card_response is required to continue authentication")
            })?;
            session
                .card_tx
                .send(card)
                .map_err(|_| ProtocolError::internal("session worker unavailable"))?;
            recv_out(&session).await?
        };

        session.touch();

        let mut value = match out {
            Out::Frame {
                code,
                frame,
                timeout_ms,
            } => {
                inner.expect = Expect::Card;
                inner.auth_frames = inner.auth_frames.saturating_add(1);
                let step = if inner.auth_frames <= 1 {
                    "auth1"
                } else {
                    "auth2"
                };
                json!({
                    "phase": "mutual_authentication",
                    "step": step,
                    "command": command_json(code, &frame, timeout_ms),
                })
            }
            Out::AuthComplete {
                issue_id,
                issue_parameter,
                session: material,
            } => {
                inner.expect = Expect::Control;
                // The authentication is finished and the client now holds the
                // session material: drop the session so no key state lingers here.
                self.remove_session(&session_id);
                json!({
                    "phase": "mutual_authentication",
                    "step": "complete",
                    "result": {
                        "issue_id": hex::encode(issue_id),
                        "issue_parameter": hex::encode(issue_parameter),
                        "session": secure_session_json(&material),
                    },
                })
            }
            Out::Error(err) => {
                inner.expect = Expect::Control;
                return Err(err);
            }
        };

        value["session_id"] = json!(session_id);
        if starting {
            value["session_created"] = json!(created);
        }
        Ok(value)
    }
}

impl Session {
    fn touch(&self) {
        *self.last_seen.lock().unwrap() = Instant::now();
    }
}

async fn recv_out(session: &Session) -> Result<Out, ProtocolError> {
    session
        .out_rx
        .recv_async()
        .await
        .map_err(|_| ProtocolError::internal("session worker terminated"))
}

/// Reject a service list that would grant more than read access.
///
/// A session can only access the services named in the authentication, so
/// constraining this list to read-only services bounds the whole session to reads:
/// the card refuses a Write on a read-only service. (The area node FeliCa also
/// requires takes part in the key derivation; it does not widen data access.)
fn enforce_read_only_nodes(services: &[u16]) -> Result<(), ProtocolError> {
    if let Some(code) = services
        .iter()
        .find(|service| !is_read_only_service(**service))
    {
        return Err(ProtocolError::forbidden(format!(
            "service 0x{code:04X} is not a read-only node"
        )));
    }
    check_service_list_shape(services).map_err(ProtocolError::bad_request)
}

fn require_nonempty(value: Option<Vec<u16>>, name: &str) -> Result<Vec<u16>, ProtocolError> {
    match value {
        Some(list) if !list.is_empty() => Ok(list),
        _ => Err(ProtocolError::bad_request(format!(
            "{name} must be a non-empty list"
        ))),
    }
}

fn command_json(code: u8, frame: &[u8], timeout_ms: u16) -> Value {
    json!({
        "code": code,
        "frame": hex::encode(frame),
        "timeout": ms_to_secs(timeout_ms),
    })
}

fn secure_session_json(material: &SecureSessionMaterial) -> Value {
    json!({
        "scheme": "des",
        "key": hex::encode(material.key),
        "transaction_id": hex::encode(material.transaction_id),
        "transaction_number": material.transaction_number,
    })
}

fn ms_to_secs(ms: u16) -> f64 {
    ms as f64 / 1000.0
}

fn new_session_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Extract the ephemeral session material established by the authentication.
fn secure_session_material(
    felica: &FelicaStandard<'_, RelayDriver>,
) -> Result<SecureSessionMaterial, ProtocolError> {
    let context = felica.authenticated_context().ok_or_else(|| {
        ProtocolError::internal("authenticated context missing after mutual authentication")
    })?;
    let key = match context.credentials() {
        SecureSessionCredentialsRef::Des(key) => *key,
        _ => {
            return Err(ProtocolError::internal(
                "unexpected secure session scheme (expected DES)",
            ))
        }
    };
    Ok(SecureSessionMaterial {
        key,
        transaction_id: *context.transaction_id(),
        transaction_number: context.transaction_number(),
    })
}

/// The per-session worker loop: run mutual authentication via `felica-rs` through
/// the relay driver, then report the session material for the client to use.
fn run_session(
    idm: [u8; 8],
    pmm: [u8; 8],
    keystore: Arc<KeyStore>,
    control_rx: flume::Receiver<StartAuth>,
    card_rx: flume::Receiver<Vec<u8>>,
    out_tx: flume::Sender<Out>,
) {
    let mut driver = RelayDriver::new(idm.to_vec(), pmm.to_vec(), out_tx.clone(), card_rx);
    let (mut felica, _poll) = match FelicaStandard::polling(&mut driver, "212F", 0xFFFF, 0x00, 0x00)
    {
        Ok(value) => value,
        Err(err) => {
            let _ = out_tx.send(Out::Error(map_felica_error(&err)));
            return;
        }
    };

    while let Ok(request) = control_rx.recv() {
        let derived = match keystore.derive_service_keys(
            request.system_code,
            &idm,
            &request.areas,
            &request.services,
        ) {
            Ok(keys) => keys,
            Err(err) => {
                let _ = out_tx.send(Out::Error(err));
                continue;
            }
        };
        let service_codes: Vec<ServiceCode> = request
            .services
            .iter()
            .map(|code| ServiceCode::new(*code))
            .collect();

        let out = match felica.mutual_authentication(
            &request.areas,
            &service_codes,
            &derived.group,
            &derived.user,
        ) {
            Ok(result) => match secure_session_material(&felica) {
                Ok(session) => Out::AuthComplete {
                    issue_id: result.issue_id,
                    issue_parameter: result.issue_parameter,
                    session,
                },
                Err(err) => Out::Error(err),
            },
            Err(err) => Out::Error(map_felica_error(&err)),
        };
        // The session key belongs to the client from here on; don't keep it.
        felica.clear_authenticated_context();
        let _ = out_tx.send(out);
    }
}
