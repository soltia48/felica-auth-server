//! Which nodes a caller is allowed to authenticate.
//!
//! Because the client receives the session key and then drives the encrypted
//! commands itself, the server's remaining lever over what a client can *do* is
//! the set of nodes it agrees to authenticate. Restricting authentication to
//! read-only services means the card itself will refuse any Write in that
//! session.

use felica_rs::felica_standard::ServiceCode;

/// FeliCa service attributes that grant read-only access, in both the
/// "with key" and "without key" variants:
///
/// | Attribute  | Meaning                     |
/// |------------|-----------------------------|
/// | `0b001010` | Random read-only with key   |
/// | `0b001011` | Random read-only without key|
/// | `0b001110` | Cyclic read-only with key   |
/// | `0b001111` | Cyclic read-only without key|
/// | `0b010110` | Purse read-only with key    |
/// | `0b010111` | Purse read-only without key |
pub fn is_read_only_service(service_code: u16) -> bool {
    matches!(
        ServiceCode::new(service_code).attributes(),
        0b001010 | 0b001011 | 0b001110 | 0b001111 | 0b010110 | 0b010111
    )
}

/// The system node, which may appear in a service code list.
const SYSTEM_NODE_CODE: u16 = 0xFFFF;

/// Reject a service list the card itself would refuse, so the caller gets a clear
/// error instead of an opaque authentication failure. A FeliCa service code list
/// must contain at least one node that requires a key, and every key-requiring
/// node must come before any key-free one.
pub fn check_service_list_shape(services: &[u16]) -> Result<(), String> {
    let mut has_key_required = false;
    let mut seen_key_free = false;
    for &raw in services {
        // The system node is authentication-required even though its low bit
        // reads as key-free.
        if raw == SYSTEM_NODE_CODE || ServiceCode::new(raw).requires_key() {
            if seen_key_free {
                return Err(format!(
                    "service 0x{raw:04X} requires a key and must be listed before key-free services"
                ));
            }
            has_key_required = true;
        } else {
            seen_key_free = true;
        }
    }
    if !has_key_required {
        return Err("services must include at least one node that requires a key".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_attributes_are_accepted_with_and_without_key() {
        for attributes in [0b001010, 0b001011, 0b001110, 0b001111, 0b010110, 0b010111] {
            let code = (0x0001 << 6) | attributes;
            assert!(
                is_read_only_service(code),
                "0x{code:04X} (attr {attributes:06b}) should be read-only"
            );
        }
    }

    #[test]
    fn writable_and_purse_mutating_attributes_are_rejected() {
        // read/write (random & cyclic), purse direct / cashback / decrement.
        for attributes in [
            0b001000, 0b001001, 0b001100, 0b001101, 0b010000, 0b010001, 0b010010, 0b010011,
            0b010100, 0b010101,
        ] {
            let code = (0x0001 << 6) | attributes;
            assert!(
                !is_read_only_service(code),
                "0x{code:04X} (attr {attributes:06b}) should not be read-only"
            );
        }
    }

    #[test]
    fn area_codes_are_not_read_only_services() {
        // Area codes carry attribute 0b000000 and must never pass the check.
        assert!(!is_read_only_service(0x0000));
        assert!(!is_read_only_service(0x1000));
    }

    #[test]
    fn service_list_shape_matches_the_card_rules() {
        // 0x008A requires a key, 0x00CB does not.
        assert!(check_service_list_shape(&[0x008A]).is_ok());
        assert!(check_service_list_shape(&[0x008A, 0x00CB]).is_ok());
        assert!(check_service_list_shape(&[0xFFFF]).is_ok());

        // Key-free only: nothing to authenticate with.
        let err = check_service_list_shape(&[0x00CB]).unwrap_err();
        assert!(err.contains("at least one node that requires a key"));

        // Key-requiring node after a key-free one.
        let err = check_service_list_shape(&[0x00CB, 0x008A]).unwrap_err();
        assert!(err.contains("must be listed before key-free services"));

        let err = check_service_list_shape(&[]).unwrap_err();
        assert!(err.contains("at least one node that requires a key"));
    }
}
