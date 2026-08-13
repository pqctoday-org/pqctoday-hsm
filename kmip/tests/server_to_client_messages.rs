//! §6.2 server-to-client message encoding — `Notify` and `Put`.
//!
//! These are the only KMIP requests this server ORIGINATES, so they are the
//! only ones whose encoder has no decoder on the same side to keep it honest:
//! for every client request, a wrong encoding shows up immediately as a failed
//! round-trip against the OASIS corpus. Nothing in that corpus exercises §6.2
//! (it is a client-driven suite), so these tests are the whole safety net for
//! the wire shape, and they check it field by field against the spec tables
//! rather than against a golden blob nobody can audit.

use pqctoday_kmip::codec::{decode_one, Value};
use pqctoday_kmip::kmip30::attrs::Attribute;
use pqctoday_kmip::kmip30::ops::{NotifyRequest, PutFunction, PutRequest};
use pqctoday_kmip::kmip30::wire::{
    decode_server_to_client_message, encode_notify_message, encode_put_message,
    encode_server_to_client_ack, ServerToClientMessage,
};
use pqctoday_kmip::kmip30::Operation;

const TS: i64 = 1_775_000_000;

/// Walk to a named child, returning its value.
fn child<'a>(frame: &'a pqctoday_kmip::codec::TtlvFrame, tag: u32) -> Option<&'a Value> {
    match &frame.value {
        Value::Structure(children) => children.iter().find(|c| c.tag.0 == tag).map(|c| &c.value),
        _ => None,
    }
}

fn structure(v: &Value) -> &Vec<pqctoday_kmip::codec::TtlvFrame> {
    match v {
        Value::Structure(c) => c,
        other => panic!("expected Structure, got {other:?}"),
    }
}

/// The message must be a RequestMessage — a Notify is a REQUEST the server
/// makes, not a response. Encoding it as a response would leave the client with
/// nothing to answer, and §6.2.2 requires it to answer.
#[test]
fn notify_is_encoded_as_a_request_message_with_the_notify_operation() {
    let bytes = encode_notify_message(
        &NotifyRequest {
            unique_identifier: "uid-1".into(),
            attributes: vec![],
            deleted_attributes: vec![],
        },
        TS,
    );
    let frame = decode_one(&bytes).expect("decodes as TTLV");
    assert_eq!(frame.tag.0, 0x42_0078, "outer tag must be Request Message");

    let batch = structure(&frame.value)
        .iter()
        .find(|c| c.tag.0 == 0x42_000f)
        .expect("Batch Item");
    assert_eq!(
        child(batch, 0x42_005c),
        Some(&Value::Enumeration(Operation::Notify.to_wire_value())),
        "Operation must be Notify (0x1b)"
    );
}

#[test]
fn notify_carries_uid_changed_attributes_and_deleted_references() {
    let bytes = encode_notify_message(
        &NotifyRequest {
            unique_identifier: "uid-42".into(),
            attributes: vec![Attribute::State(pqctoday_kmip::kmip30::attrs::State::Deactivated)],
            deleted_attributes: vec!["Object Group".into()],
        },
        TS,
    );

    let decoded = decode_server_to_client_message(&bytes).expect("round-trips");
    match decoded {
        ServerToClientMessage::Notify(n) => {
            assert_eq!(n.unique_identifier, "uid-42");
            assert_eq!(n.attributes.len(), 1, "the changed attribute must survive");
            assert_eq!(
                n.deleted_attributes,
                vec!["Object Group".to_string()],
                "a deleted attribute is reported by reference, not by value"
            );
        }
        other => panic!("expected Notify, got {other:?}"),
    }
}

#[test]
fn put_carries_the_function_and_only_names_a_replaced_object_when_replacing() {
    // Replace: the superseded UID is the whole point — a client receiving a
    // replacement must know what it replaces.
    let bytes = encode_put_message(
        &PutRequest {
            unique_identifier: "new-cert".into(),
            put_function: PutFunction::Replace,
            replaced_unique_identifier: Some("expiring-cert".into()),
            attributes: vec![],
        },
        TS,
    );
    match decode_server_to_client_message(&bytes).expect("round-trips") {
        ServerToClientMessage::Put(p) => {
            assert_eq!(p.put_function, PutFunction::Replace);
            assert_eq!(p.replaced_unique_identifier.as_deref(), Some("expiring-cert"));
        }
        other => panic!("expected Put, got {other:?}"),
    }

    // New: a replaced UID must NOT be emitted even if the caller supplies one.
    // Sending both would tell the client the object simultaneously is and is
    // not superseding something.
    let bytes = encode_put_message(
        &PutRequest {
            unique_identifier: "fresh".into(),
            put_function: PutFunction::New,
            replaced_unique_identifier: Some("should-not-appear".into()),
            attributes: vec![],
        },
        TS,
    );
    match decode_server_to_client_message(&bytes).expect("round-trips") {
        ServerToClientMessage::Put(p) => {
            assert_eq!(p.put_function, PutFunction::New);
            assert_eq!(
                p.replaced_unique_identifier, None,
                "Put Function = New must not carry a Replaced Unique Identifier"
            );
        }
        other => panic!("expected Put, got {other:?}"),
    }
}

/// Codepoints, checked against the CSD02 tag/enum tables rather than against
/// whatever the encoder happens to emit.
#[test]
fn put_function_and_tags_match_the_published_codepoints() {
    assert_eq!(PutFunction::New.to_wire_value(), 0x01);
    assert_eq!(PutFunction::Replace.to_wire_value(), 0x02);
    assert_eq!(PutFunction::from_wire_value(0x02), Some(PutFunction::Replace));
    assert_eq!(PutFunction::from_wire_value(0x03), None, "unknown values must not be guessed");

    let bytes = encode_put_message(
        &PutRequest {
            unique_identifier: "u".into(),
            put_function: PutFunction::New,
            replaced_unique_identifier: None,
            attributes: vec![],
        },
        TS,
    );
    let frame = decode_one(&bytes).unwrap();
    let batch = structure(&frame.value).iter().find(|c| c.tag.0 == 0x42_000f).unwrap();
    let payload = child(batch, 0x42_0079).expect("Request Payload");
    // Put Function 0x420070 — from kmip-spec-3.0-tags-enums.json (CSD02).
    assert!(
        structure(payload).iter().any(|c| c.tag.0 == 0x42_0070),
        "Put Function must be encoded at 0x420070"
    );
}

/// "The client SHALL send a response in the form of a Response containing no
/// payload" — so the ack must carry a result status and NOT a payload.
#[test]
fn the_client_ack_is_a_response_with_a_status_and_no_payload() {
    let bytes = encode_server_to_client_ack(Operation::Notify, TS);
    let frame = decode_one(&bytes).expect("decodes");
    assert_eq!(frame.tag.0, 0x42_007b, "outer tag must be Response Message");

    let batch = structure(&frame.value)
        .iter()
        .find(|c| c.tag.0 == 0x42_000f)
        .expect("Batch Item");
    assert_eq!(
        child(batch, 0x42_007f),
        Some(&Value::Enumeration(0x00)),
        "Result Status must be Success"
    );
    assert!(
        child(batch, 0x42_007c).is_none(),
        "a §6.2 acknowledgement must contain NO response payload"
    );
}

/// A client-to-server operation is not a push message; decoding one as such
/// must fail rather than be silently reinterpreted.
#[test]
fn a_non_push_operation_is_rejected_by_the_push_decoder() {
    let bytes = encode_notify_message(
        &NotifyRequest {
            unique_identifier: "u".into(),
            attributes: vec![],
            deleted_attributes: vec![],
        },
        TS,
    );
    // Rewrite the Operation enum in place: Notify (0x1b) -> Create (0x01).
    let mut tampered = bytes.clone();
    let idx = tampered
        .windows(4)
        .position(|w| w == [0x00, 0x00, 0x00, 0x1b])
        .expect("Notify opcode present");
    tampered[idx + 3] = 0x01;
    assert!(
        decode_server_to_client_message(&tampered).is_err(),
        "Create is not a §6.2 push message and must not decode as one"
    );
}
