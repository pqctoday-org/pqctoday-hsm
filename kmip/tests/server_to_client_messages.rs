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

// ── The other three item-10 operations ──────────────────────────────────────
//
// `Notify` and `Put` are pushes; these three are the server interrogating the
// client. Same direction on the wire, opposite purpose — and unlike the pushes,
// the client's answer carries a payload the server actually reads, so each one
// is tested in both directions.

/// The server asking "what do you speak?" must be a Request, and an empty
/// version list is the §6.1.21 way of saying "everything you have" — not a
/// malformed payload to be filled in with a default.
#[test]
fn discover_versions_message_is_a_request_with_the_versions_asked_for() {
    let bytes = pqctoday_kmip::kmip30::wire::encode_discover_versions_message(&[], TS);
    let frame = decode_one(&bytes).expect("decodes");
    assert_eq!(frame.tag.0, 0x42_0078, "Request Message");

    let batch = structure(child(&frame, 0x42_000f).expect("Batch Item"));
    let op = batch.iter().find(|c| c.tag.0 == 0x42_005c).expect("Operation");
    assert_eq!(
        op.value,
        Value::Enumeration(Operation::DiscoverVersions.to_wire_value()),
        "operation must be DiscoverVersions"
    );
    let payload = batch.iter().find(|c| c.tag.0 == 0x42_0079).expect("Request Payload");
    assert!(
        structure(&payload.value).is_empty(),
        "an empty request list is meaningful (§6.1.21: return everything); it must \
         not be silently populated"
    );

    // And a non-empty ask round-trips the exact pairs.
    let bytes = pqctoday_kmip::kmip30::wire::encode_discover_versions_message(&[(3, 0), (2, 1)], TS);
    match decode_server_to_client_message(&bytes).expect("decodes") {
        ServerToClientMessage::DiscoverVersions(req) => {
            assert_eq!(req.protocol_versions, vec![(3, 0), (2, 1)]);
        }
        other => panic!("expected DiscoverVersions, got {other:?}"),
    }
}

/// A server-issued `Query` carries Query Functions, and the one that matters
/// for pushing is Query Operations.
#[test]
fn query_message_carries_the_requested_query_functions() {
    use pqctoday_kmip::kmip30::ops::QueryFunction;
    let bytes = pqctoday_kmip::kmip30::wire::encode_query_message(
        &[QueryFunction::QueryOperations],
        TS,
    );
    match decode_server_to_client_message(&bytes).expect("decodes") {
        ServerToClientMessage::Query(functions) => {
            assert_eq!(functions, vec![QueryFunction::QueryOperations]);
        }
        other => panic!("expected Query, got {other:?}"),
    }
}

/// The handback. The field names the role the RECIPIENT applies, so returning
/// the peer to the client role is what makes us the server again — sending
/// `Server` here would tell the peer to stay put, which is the opposite.
#[test]
fn set_endpoint_role_handback_tells_the_peer_to_become_the_client() {
    use pqctoday_kmip::kmip30::EndpointRole;
    let bytes =
        pqctoday_kmip::kmip30::wire::encode_set_endpoint_role_message(EndpointRole::Client, TS);
    match decode_server_to_client_message(&bytes).expect("decodes") {
        ServerToClientMessage::SetEndpointRole(req) => {
            assert_eq!(req.endpoint_role, EndpointRole::Client);
        }
        other => panic!("expected SetEndpointRole, got {other:?}"),
    }
}

/// None of the three names a managed object, so requiring a Unique Identifier
/// (as the push decoder does) would reject every one of them. This pins that
/// the decoder branches before that check rather than after it.
#[test]
fn interrogation_messages_decode_without_a_unique_identifier() {
    use pqctoday_kmip::kmip30::ops::QueryFunction;
    use pqctoday_kmip::kmip30::EndpointRole;
    for bytes in [
        pqctoday_kmip::kmip30::wire::encode_discover_versions_message(&[(3, 0)], TS),
        pqctoday_kmip::kmip30::wire::encode_query_message(&[QueryFunction::QueryOperations], TS),
        pqctoday_kmip::kmip30::wire::encode_set_endpoint_role_message(EndpointRole::Client, TS),
    ] {
        assert!(
            decode_server_to_client_message(&bytes).is_ok(),
            "an interrogation message must decode without a Unique Identifier"
        );
    }
}

// ── The client's answers, as the server reads them ──────────────────────────

/// A Discover Versions answer must survive the trip back as the same pairs —
/// this is the value the server intersects against its own list, so a decode
/// that silently drops entries would look exactly like an incompatible peer.
#[test]
fn client_discover_versions_answer_round_trips() {
    use pqctoday_kmip::kmip30::wire::{decode_client_response, ClientResponsePayload};
    let bytes = pqctoday_kmip::kmip30::wire::encode_discover_versions_client_response(
        &[(3, 0), (2, 1)],
        TS,
    );
    let resp = decode_client_response(&bytes).expect("decodes");
    assert!(resp.succeeded());
    assert_eq!(resp.operation, Some(Operation::DiscoverVersions));
    match resp.payload {
        ClientResponsePayload::DiscoverVersions(v) => assert_eq!(v, vec![(3, 0), (2, 1)]),
        other => panic!("expected a version list, got {other:?}"),
    }
}

/// A Query answer round-trips as the operation list the server gates pushes on.
#[test]
fn client_query_answer_round_trips_the_operation_list() {
    use pqctoday_kmip::kmip30::wire::{decode_client_response, ClientResponsePayload};
    let bytes = pqctoday_kmip::kmip30::wire::encode_query_client_response(
        &[Operation::Notify, Operation::Put],
        TS,
    );
    match decode_client_response(&bytes).expect("decodes").payload {
        ClientResponsePayload::Query(ops) => {
            assert_eq!(ops, vec![Operation::Notify, Operation::Put]);
        }
        other => panic!("expected an operation list, got {other:?}"),
    }
}

/// An empty operation list is a real answer — "I can service nothing" — and
/// must NOT decode to the same thing as no answer at all, because the server
/// treats those two cases oppositely (drop everything vs. push everything).
#[test]
fn an_empty_query_answer_is_not_the_same_as_no_answer() {
    use pqctoday_kmip::kmip30::wire::{decode_client_response, ClientResponsePayload};
    let answered = pqctoday_kmip::kmip30::wire::encode_query_client_response(&[], TS);
    assert_eq!(
        decode_client_response(&answered).expect("decodes").payload,
        ClientResponsePayload::Query(vec![]),
        "an empty list must survive as an empty list"
    );

    let silent = encode_server_to_client_ack(Operation::Query, TS);
    assert_eq!(
        decode_client_response(&silent).expect("decodes").payload,
        ClientResponsePayload::None,
        "a no-payload acknowledgement must stay distinguishable from an empty list"
    );
}

/// The §6.2 acknowledgement still decodes as "no payload" — the push path was
/// working before these three operations existed and must keep working.
#[test]
fn push_acknowledgement_still_decodes_as_no_payload() {
    use pqctoday_kmip::kmip30::wire::{decode_client_response, ClientResponsePayload};
    let bytes = encode_server_to_client_ack(Operation::Notify, TS);
    let resp = decode_client_response(&bytes).expect("decodes");
    assert_eq!(resp.operation, Some(Operation::Notify));
    assert!(resp.succeeded());
    assert_eq!(resp.payload, ClientResponsePayload::None);
}
