use super::{fixture, recovery_grant::*};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair},
};
use serde_json::{json, Value};

pub(super) fn key() -> signature::EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 =
        signature::EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .unwrap();
    signature::EcdsaKeyPair::from_pkcs8(
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .unwrap()
}

pub(super) fn header() -> Value {
    json!({"alg":"ES256", "kid":"fixture-key", "typ":"proximi-recovery+jwt"})
}

pub(super) fn claims() -> Value {
    json!({"version":1, "iss":"proximi-operator-recovery",
        "aud":"proximi-recovery", "action":"replace_primary",
        "install_id":"fixture-install", "region":"eu", "grant_id":([8;32]),
        "iat":100, "nbf":100, "exp":200, "plan":fixture().1, "fencing_ref":([7;32])})
}

fn sign_raw(key: &signature::EcdsaKeyPair, header: &str, claims: &str) -> String {
    let input = format!("{}.{}", B64.encode(header), B64.encode(claims));
    let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
    format!("{input}.{}", B64.encode(sig.as_ref()))
}

fn sign(key: &signature::EcdsaKeyPair, header: &Value, claims: &Value) -> String {
    sign_raw(key, &header.to_string(), &claims.to_string())
}

pub(super) fn context(key: &signature::EcdsaKeyPair) -> Context {
    Context {
        profile: terrapi_vesta_replication::recovery::grant::Profile {
            issuer: "proximi-operator-recovery".into(),
            audience: "proximi-recovery".into(),
            token_type: "proximi-recovery+jwt".into(),
        },
        keys: vec![("fixture-key".into(), key.public_key().as_ref().to_vec())],
        now: 150,
        max_lifetime: 100,
        install_id: "fixture-install".into(),
        region: "eu".into(),
        // Trusted assertions only, NOT an implemented registry or fencing check.
        reservation: Some(Reservation {
            plan: fixture().1,
            grant_id: [8; 32],
            fencing_ref: [7; 32],
        }),
        fencing_confirmed: true,
    }
}

#[test]
fn valid_signature_is_stateless_and_does_not_activate_membership() {
    let key = key();
    let token = sign(&key, &header(), &claims());
    let ctx = context(&key);
    let verified = verify(&token, &ctx).unwrap();
    assert_eq!(verified.plan, fixture().1);
    assert_eq!(verified.grant_id, [8; 32]);
    // Retry is accepted; single-use/CAS protection belongs to the future registry.
    assert_eq!(verify(&token, &ctx).unwrap(), verified);
    let (m, p) = fixture();
    assert!(!m.write_eligible(&p, p.candidate, true));
}

#[test]
fn rejects_untrusted_keys_algorithms_and_header_extensions() {
    let key = key();
    let ctx = context(&key);
    for (field, value) in [
        ("alg", json!("none")),
        ("alg", json!("HS256")),
        ("kid", json!("unknown")),
        ("typ", json!("JWT")),
        ("jku", json!("https://untrusted.invalid/keys")),
        ("x5u", json!("file:///key")),
        ("crit", json!(["exp"])),
        ("b64", json!(false)),
    ] {
        let mut h = header();
        h[field] = value;
        assert!(verify(&sign(&key, &h, &claims()), &ctx).is_err(), "{field}");
    }
    assert!(verify(&sign(&self::key(), &header(), &claims()), &ctx).is_err());
    let token = sign(&key, &header(), &claims());
    let mut revoked = context(&key);
    revoked.keys.clear();
    assert!(verify(&token, &revoked).is_err());
    let mut ambiguous = context(&key);
    ambiguous.keys.push(ambiguous.keys[0].clone());
    assert!(verify(&token, &ambiguous).is_err());
}

#[test]
fn rejects_signed_wrong_purpose_scope_and_authority_bindings() {
    let key = key();
    let ctx = context(&key);
    for (field, value) in [
        ("version", json!(2)),
        ("iss", json!("identity")),
        ("aud", json!("proximi-install")),
        ("action", json!("operate")),
        ("install_id", json!("other")),
        ("region", json!("uae")),
        ("grant_id", json!(([9; 32]))),
        ("fencing_ref", json!(([9; 32]))),
        ("unexpected", json!(true)),
    ] {
        let mut c = claims();
        c[field] = value;
        assert!(verify(&sign(&key, &header(), &c), &ctx).is_err(), "{field}");
    }
    let token = sign(&key, &header(), &claims());
    let mut missing = context(&key);
    missing.reservation = None;
    assert!(verify(&token, &missing).is_err());
    let mut unfenced = context(&key);
    unfenced.fencing_confirmed = false;
    assert!(verify(&token, &unfenced).is_err());
    let mut stale = context(&key);
    stale.reservation.as_mut().unwrap().plan.revision += 1;
    assert!(verify(&token, &stale).is_err());
}

#[test]
fn every_plan_field_is_bound_and_nested_extensions_are_rejected() {
    let key = key();
    let ctx = context(&key);
    for pointer in [
        "/plan/recovery_id",
        "/plan/revision",
        "/plan/candidate",
        "/plan/baseline/scope",
        "/plan/baseline/revision",
        "/plan/baseline/digest",
        "/plan/baseline/old_primary",
        "/plan/baseline/survivor",
        "/plan/baseline/survivor_generation",
        "/plan/baseline/checkpoint",
    ] {
        let mut c = claims();
        let v = c.pointer_mut(pointer).unwrap();
        *v = if v.is_string() {
            json!("other")
        } else if v.is_number() {
            json!(99)
        } else {
            json!(([99; 32]))
        };
        assert!(
            verify(&sign(&key, &header(), &c), &ctx).is_err(),
            "{pointer}"
        );
    }
    for pointer in ["/plan", "/plan/baseline"] {
        let mut c = claims();
        c.pointer_mut(pointer).unwrap()["extra"] = json!(true);
        assert!(verify(&sign(&key, &header(), &c), &ctx).is_err());
    }
    // Even a matching trusted fixture cannot authorize a structurally invalid plan.
    let mut bad = context(&key);
    let mut c = claims();
    bad.reservation.as_mut().unwrap().plan.candidate = fixture().1.baseline.old_primary;
    c["plan"] = serde_json::to_value(&bad.reservation.as_ref().unwrap().plan).unwrap();
    assert!(verify(&sign(&key, &header(), &c), &bad).is_err());
}

#[test]
fn validates_time_boundaries_without_overflow_or_implicit_leeway() {
    let key = key();
    let ctx = context(&key);
    for (iat, nbf, exp) in [
        (151, 151, 200),
        (100, 151, 200),
        (100, 100, 150),
        (100, 100, 100),
        (100, 99, 200),
        (100, 100, 201),
        (u64::MAX, 100, 200),
        (100, 100, u64::MAX),
    ] {
        let mut c = claims();
        c["iat"] = json!(iat);
        c["nbf"] = json!(nbf);
        c["exp"] = json!(exp);
        assert!(verify(&sign(&key, &header(), &c), &ctx).is_err());
    }
    let token = sign(&key, &header(), &claims());
    for now in [100, 199] {
        let mut ctx = context(&key);
        ctx.now = now;
        assert!(verify(&token, &ctx).is_ok());
    }
    let mut ctx = context(&key);
    ctx.max_lifetime = 0;
    assert!(verify(&token, &ctx).is_err());
}

#[test]
fn rejects_duplicate_missing_and_wrongly_typed_claims() {
    let key = key();
    let ctx = context(&key);
    let c = claims().to_string();
    for raw in [
        c.replacen('{', "{\"exp\":199,", 1),
        c.replacen("\"plan\":{", "\"plan\":{\"revision\":5,", 1),
        c.replacen("\"baseline\":{", "\"baseline\":{\"revision\":4,", 1),
    ] {
        assert!(verify(&sign_raw(&key, &header().to_string(), &raw), &ctx).is_err());
    }
    let h = header().to_string().replacen('{', "{\"alg\":\"ES256\",", 1);
    assert!(verify(&sign_raw(&key, &h, &c), &ctx).is_err());
    for field in claims().as_object().unwrap().keys() {
        let mut c = claims();
        c.as_object_mut().unwrap().remove(field);
        assert!(
            verify(&sign(&key, &header(), &c), &ctx).is_err(),
            "missing {field}"
        );
    }
    for value in [json!(-1), json!(150.5), json!("150"), Value::Null] {
        let mut c = claims();
        c["iat"] = value;
        assert!(verify(&sign(&key, &header(), &c), &ctx).is_err());
    }
}

#[test]
fn rejects_tampering_malformed_encoding_and_oversize_tokens() {
    let key = key();
    let ctx = context(&key);
    let token = sign(&key, &header(), &claims());
    let parts: Vec<_> = token.split('.').collect();
    for bad in [
        String::new(),
        format!("{token}.extra"),
        format!("{}.{}", parts[0], parts[1]),
        format!("{}=.{}.{}", parts[0], parts[1], parts[2]),
        format!("{}.!.{}", parts[0], parts[2]),
        format!("{}.{}.", parts[0], parts[1]),
        format!("{}.{}.{}", parts[0], parts[1], B64.encode([0; 64])),
        "a".repeat(16 * 1024 + 1),
    ] {
        assert!(verify(&bad, &ctx).is_err());
    }
    let mut altered = claims();
    altered["exp"] = json!(199);
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        B64.encode(altered.to_string()),
        parts[2]
    );
    assert!(verify(&tampered, &ctx).is_err());
    // Signing input is the original wire bytes, not a reserialized JSON object.
    assert!(verify(
        &sign_raw(
            &key,
            &serde_json::to_string_pretty(&header()).unwrap(),
            &serde_json::to_string_pretty(&claims()).unwrap()
        ),
        &ctx
    )
    .is_ok());
}

#[test]
fn signed_malformed_inputs_and_empty_trusted_bindings_fail_closed() {
    let key = key();
    let ctx = context(&key);
    for payload in [
        String::new(),
        "!".into(),
        format!("{}=", B64.encode(claims().to_string())),
    ] {
        let input = format!("{}.{}", B64.encode(header().to_string()), payload);
        let sig = key.sign(&SystemRandom::new(), input.as_bytes()).unwrap();
        assert!(verify(&format!("{input}.{}", B64.encode(sig.as_ref())), &ctx).is_err());
    }
    for raw in ["null", "{}", "{", "[]"] {
        assert!(verify(&sign_raw(&key, &header().to_string(), raw), &ctx).is_err());
    }
    let oversized_header = format!("{}{}", " ".repeat(1024), header());
    assert!(verify(
        &sign_raw(&key, &oversized_header, &claims().to_string()),
        &ctx
    )
    .is_err());
    for field in ["grant_id", "fencing_ref", "install_id", "region"] {
        let mut c = claims();
        let mut ctx = context(&key);
        match field {
            "grant_id" => {
                c[field] = json!(([0; 32]));
                ctx.reservation.as_mut().unwrap().grant_id = [0; 32];
            }
            "fencing_ref" => {
                c[field] = json!(([0; 32]));
                ctx.reservation.as_mut().unwrap().fencing_ref = [0; 32];
            }
            "install_id" => {
                c[field] = json!("");
                ctx.install_id.clear();
            }
            "region" => {
                c[field] = json!("");
                ctx.region.clear();
            }
            _ => unreachable!(),
        }
        assert!(verify(&sign(&key, &header(), &c), &ctx).is_err());
    }
}
