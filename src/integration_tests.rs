//! End-to-end tests driving the relay against `felica-rs`'s in-memory card
//! emulator. The test plays the role of the reader-owning *client*: it forwards
//! each authentication frame the server emits to the emulated card and feeds the
//! card's response back on the next request. Once authentication completes it
//! takes the returned session material and performs the encrypted Read **itself**,
//! exactly as a real client would — the server never sees the card data.

use std::sync::Arc;
use std::time::Duration;

use felica_rs::felica_standard::{
    AuthenticatedContext, BlockListElement, EmulatedArea, EmulatedService, EmulatedSystem,
    FelicaDriver, FelicaStandard, FelicaStandardEmulator, SecureSessionCredentials, ServiceCode,
    Type3TagPollingResult,
};
use felica_rs::{DriverError, RemoteTarget};

use crate::keystore::KeyStore;
use crate::session::{MutualAuthInput, SessionManager};

const SYSTEM_CODE: u16 = 0x0003;
/// Area holding the writable service (`0x0040..=0x007F`).
const AREA_RW: u16 = 0x0040;
/// Area holding the read-only services (`0x0080..=0x00FF`).
const AREA_RO: u16 = 0x0080;
/// Random read/write **with key** — writable, so read-only mode must refuse it.
const SERVICE_CODE: u16 = 0x0048;
/// Random read-only **with key** (attribute `0b001010`).
const SERVICE_RO: u16 = 0x008A;
/// Random read-only **without key** (attribute `0b001011`).
const SERVICE_RO_NOKEY: u16 = 0x00CB;
const IDM: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
const PMM: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const K_SYS: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
const K_AREA_RW: [u8; 8] = [0x21, 0x43, 0x65, 0x87, 0xA9, 0xCB, 0xED, 0x0F];
const K_AREA_RO: [u8; 8] = [0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21];
const K_SVC: [u8; 8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
const K_SVC_RO: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
const ISSUE_ID: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33];
const ISSUE_PARAM: [u8; 8] = [0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB];
const BLOCK: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
];

fn keystore() -> KeyStore {
    let jsonl = format!(
        concat!(
            r#"{{"system_code":"0003","node":"FFFF","algo":"DES","idm":null,"key":"{sys}"}}"#,
            "\n",
            r#"{{"system_code":"0003","node":"0040","algo":"DES","idm":null,"key":"{area_rw}"}}"#,
            "\n",
            r#"{{"system_code":"0003","node":"0080","algo":"DES","idm":null,"key":"{area_ro}"}}"#,
            "\n",
            r#"{{"system_code":"0003","node":"0048","algo":"DES","idm":null,"key":"{svc}"}}"#,
            "\n",
            r#"{{"system_code":"0003","node":"008A","algo":"DES","idm":null,"key":"{svc_ro}"}}"#,
            "\n",
        ),
        sys = hex::encode(K_SYS),
        area_rw = hex::encode(K_AREA_RW),
        area_ro = hex::encode(K_AREA_RO),
        svc = hex::encode(K_SVC),
        svc_ro = hex::encode(K_SVC_RO),
    );
    KeyStore::from_reader(jsonl.as_bytes()).expect("keys should parse")
}

/// A small card holding one writable service and two read-only ones (with and
/// without key), each under its own area so the tests can authenticate either set.
fn emulated_card() -> FelicaStandardEmulator {
    let mut system = EmulatedSystem::new(SYSTEM_CODE, IDM, PMM).expect("system");
    system.set_system_key(K_SYS);
    system.set_issue_information(ISSUE_ID, ISSUE_PARAM);

    let mut writable_area = EmulatedArea::new(AREA_RW, 0x007F).expect("writable area");
    writable_area.set_key(K_AREA_RW);
    let mut writable =
        EmulatedService::with_blocks(ServiceCode::new(SERVICE_CODE), 0x0000, vec![BLOCK]);
    writable.set_key(K_SVC);
    writable_area
        .add_service(writable)
        .expect("writable service fits its area");
    system.add_area(writable_area).expect("writable area fits");

    let mut read_only_area = EmulatedArea::new(AREA_RO, 0x00FF).expect("read-only area");
    read_only_area.set_key(K_AREA_RO);
    let mut read_only =
        EmulatedService::with_blocks(ServiceCode::new(SERVICE_RO), 0x0000, vec![BLOCK]);
    read_only.set_key(K_SVC_RO);
    read_only_area
        .add_service(read_only)
        .expect("read-only service fits its area");
    let read_only_no_key =
        EmulatedService::with_blocks(ServiceCode::new(SERVICE_RO_NOKEY), 0xFFFF, vec![BLOCK]);
    read_only_area
        .add_service(read_only_no_key)
        .expect("keyless read-only service fits its area");
    system
        .add_area(read_only_area)
        .expect("read-only area fits");

    let mut emulator = FelicaStandardEmulator::new();
    emulator.add_system(system);
    emulator
}

/// A client-side driver that talks straight to the emulated card. This is what a
/// real client owns; the server never gets access to it.
struct CardDriver<'a> {
    emulator: &'a mut FelicaStandardEmulator,
}

impl FelicaDriver for CardDriver<'_> {
    fn detect_type_f(
        &mut self,
        _target: &RemoteTarget,
        _system_code: u16,
        _request_code: u8,
        _time_slots: u8,
    ) -> Result<Type3TagPollingResult, DriverError> {
        Ok(Type3TagPollingResult {
            idm: IDM.to_vec(),
            pmm: PMM.to_vec(),
            optional: Vec::new(),
        })
    }

    fn transceive(
        &mut self,
        _target: &RemoteTarget,
        data: &[u8],
        _timeout_ms: Option<u16>,
    ) -> Result<Vec<u8>, DriverError> {
        self.emulator
            .handle_frame(data)
            .ok_or_else(|| DriverError::Other("emulated card rejected the frame".into()))
    }
}

/// Relay a hex command frame to the emulated card and return its raw response.
fn relay_to_card(emulator: &mut FelicaStandardEmulator, frame_hex: &str) -> Vec<u8> {
    let frame = hex::decode(frame_hex).expect("frame should be valid hex");
    match emulator.handle_frame(&frame) {
        Some(response) => response,
        None => panic!(
            "emulated card rejected command 0x{:02X} (frame {frame_hex})",
            frame.get(1).copied().unwrap_or(0)
        ),
    }
}

fn start_input(areas: Vec<u16>, services: Vec<u16>) -> MutualAuthInput {
    MutualAuthInput {
        idm: Some(IDM),
        pmm: Some(PMM),
        system_code: Some(SYSTEM_CODE),
        areas: Some(areas),
        services: Some(services),
        ..Default::default()
    }
}

fn card_input(session_id: &str, card_response: Vec<u8>) -> MutualAuthInput {
    MutualAuthInput {
        session_id: Some(session_id.to_string()),
        card_response: Some(card_response),
        ..Default::default()
    }
}

/// The ephemeral session material the server hands back.
struct SessionMaterial {
    key: [u8; 8],
    transaction_id: [u8; 6],
    transaction_number: u16,
}

fn manager(read_only_nodes: bool) -> Arc<SessionManager> {
    SessionManager::new(
        Arc::new(keystore()),
        read_only_nodes,
        Duration::from_secs(60),
        16,
    )
}

/// Run the three-step mutual authentication and return the manager, the emulated
/// card, the session id and the session material handed to the client.
async fn authenticate(
    read_only_nodes: bool,
    areas: Vec<u16>,
    services: Vec<u16>,
) -> (
    Arc<SessionManager>,
    FelicaStandardEmulator,
    String,
    SessionMaterial,
) {
    let manager = manager(read_only_nodes);
    let mut card = emulated_card();

    let response = manager
        .handle_mutual_authentication(start_input(areas, services))
        .await
        .expect("auth start should succeed");
    assert_eq!(response["step"], "auth1");
    assert_eq!(response["session_created"], true);
    assert_eq!(response["command"]["code"], 0x10);
    let session_id = response["session_id"].as_str().unwrap().to_string();
    let card_response = relay_to_card(&mut card, response["command"]["frame"].as_str().unwrap());

    let response = manager
        .handle_mutual_authentication(card_input(&session_id, card_response))
        .await
        .expect("auth step 2 should succeed");
    assert_eq!(response["step"], "auth2");
    assert_eq!(response["command"]["code"], 0x12);
    let card_response = relay_to_card(&mut card, response["command"]["frame"].as_str().unwrap());

    let response = manager
        .handle_mutual_authentication(card_input(&session_id, card_response))
        .await
        .expect("auth completion should succeed");
    assert_eq!(response["step"], "complete");
    assert_eq!(response["result"]["issue_id"], hex::encode(ISSUE_ID));
    assert_eq!(
        response["result"]["issue_parameter"],
        hex::encode(ISSUE_PARAM)
    );

    let session = &response["result"]["session"];
    assert_eq!(session["scheme"], "des");
    let key: [u8; 8] = hex::decode(session["key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .expect("session key is 8 bytes");
    let transaction_id: [u8; 6] = hex::decode(session["transaction_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .expect("transaction id is 6 bytes");
    let transaction_number = session["transaction_number"].as_u64().unwrap() as u16;

    (
        manager,
        card,
        session_id,
        SessionMaterial {
            key,
            transaction_id,
            transaction_number,
        },
    )
}

/// Rebuild the secure session on the client side from the returned material.
fn client_session<'a>(
    card: &'a mut FelicaStandardEmulator,
    material: &SessionMaterial,
) -> FelicaStandard<'a, CardDriver<'a>> {
    // Leaked so the returned `FelicaStandard` can borrow it for the whole test;
    // this is a test-only convenience.
    let driver: &'a mut CardDriver<'a> = Box::leak(Box::new(CardDriver { emulator: card }));
    let (mut felica, _poll) = FelicaStandard::polling(driver, "212F", SYSTEM_CODE, 0x00, 0x00)
        .expect("client-side polling should succeed");
    felica.set_authenticated_context(AuthenticatedContext::new(
        material.transaction_number,
        material.transaction_id,
        SecureSessionCredentials::Des(material.key),
    ));
    felica
}

#[tokio::test]
async fn client_reads_card_data_itself_using_returned_session_material() {
    let (_manager, mut card, _session_id, material) =
        authenticate(false, vec![AREA_RW], vec![SERVICE_CODE]).await;

    // From here on the server is not involved: the client rebuilds the secure
    // session locally and performs the encrypted Read against the card.
    let mut felica = client_session(&mut card, &material);
    let blocks = felica
        .read(&[BlockListElement::new(0, 0, 0)])
        .expect("client-side encrypted read should succeed");
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0], BLOCK, "client decrypted the real block data");
}

#[tokio::test]
async fn read_only_mode_authenticates_a_read_only_service_and_the_card_refuses_writes() {
    let (_manager, mut card, _session_id, material) =
        authenticate(true, vec![AREA_RO], vec![SERVICE_RO]).await;

    let mut felica = client_session(&mut card, &material);
    let blocks = felica
        .read(&[BlockListElement::new(0, 0, 0)])
        .expect("reading through a read-only service should succeed");
    assert_eq!(blocks[0], BLOCK);

    // The card itself rejects a Write on a read-only service — the point of the
    // restriction: the session key cannot be used to modify data.
    let write = felica.write(&[BlockListElement::new(0, 0, 0)], &[0xFF; 16]);
    assert!(
        write.is_err(),
        "card must refuse writes on a read-only node"
    );
}

#[tokio::test]
async fn read_only_mode_authenticates_a_keyless_read_only_service() {
    // A "without key" node contributes no key to the derivation on either side.
    // The card requires at least one key-requiring node, so it is listed first.
    let (_manager, mut card, _session_id, material) =
        authenticate(true, vec![AREA_RO], vec![SERVICE_RO, SERVICE_RO_NOKEY]).await;

    let mut felica = client_session(&mut card, &material);
    // Service index 1 is the keyless read-only service — the second entry of the
    // authenticated service list.
    let blocks = felica
        .read(&[BlockListElement::new(0, 1, 0)])
        .expect("reading through a keyless read-only service should succeed");
    assert_eq!(blocks[0], BLOCK);
}

#[tokio::test]
async fn read_only_mode_rejects_a_writable_service() {
    let manager = manager(true);

    let err = manager
        .handle_mutual_authentication(start_input(vec![AREA_RW], vec![SERVICE_CODE]))
        .await
        .unwrap_err();
    assert_eq!(err.status, 403);
    assert!(err.message.contains("not a read-only node"));

    // The rejected request must not leave a session behind.
    assert_eq!(manager.live_sessions(), 0);
}

#[tokio::test]
async fn a_keyless_only_service_list_is_rejected_with_a_clear_error() {
    let manager = manager(true);
    let err = manager
        .handle_mutual_authentication(start_input(vec![AREA_RO], vec![SERVICE_RO_NOKEY]))
        .await
        .unwrap_err();
    assert_eq!(err.status, 400);
    assert!(err
        .message
        .contains("at least one node that requires a key"));
    assert_eq!(manager.live_sessions(), 0);
}

#[tokio::test]
async fn writable_services_are_still_allowed_when_the_restriction_is_off() {
    let manager = manager(false);
    let response = manager
        .handle_mutual_authentication(start_input(vec![AREA_RW], vec![SERVICE_CODE]))
        .await
        .expect("writable service is fine without the restriction");
    assert_eq!(response["step"], "auth1");
}

#[tokio::test]
async fn session_is_dropped_once_authentication_completes() {
    let (manager, _card, session_id, _material) =
        authenticate(false, vec![AREA_RW], vec![SERVICE_CODE]).await;

    // The server keeps no session state (nor key material) after handing the
    // session material to the client.
    assert_eq!(manager.live_sessions(), 0);

    let err = manager
        .handle_mutual_authentication(card_input(&session_id, vec![0x00]))
        .await
        .unwrap_err();
    assert_eq!(err.status, 404);
}

#[tokio::test]
async fn unknown_session_is_not_found() {
    let manager = manager(false);
    let err = manager
        .handle_mutual_authentication(card_input("deadbeef", vec![0x00]))
        .await
        .unwrap_err();
    assert_eq!(err.status, 404);
}

#[tokio::test]
async fn mutual_auth_start_requires_idm_and_pmm() {
    let manager = manager(false);
    let err = manager
        .handle_mutual_authentication(MutualAuthInput {
            system_code: Some(SYSTEM_CODE),
            areas: Some(vec![0x0000]),
            services: Some(vec![SERVICE_CODE]),
            ..Default::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.status, 400);
}
