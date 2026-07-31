mod support;

use sessionlayer_agent::identity::{self, IdentityStore, RenewAhead, RenewAheadConfig};
use sessionlayer_agent::join::{MtlsJoin, OidcJoin, TokenJoin};
use std::time::Duration;
use support::MockCp;

const CT: Duration = Duration::from_secs(5);
const RT: Duration = Duration::from_secs(10);

fn operator_material(node_name: &str) -> (String, String, p256::ecdsa::VerifyingKey) {
    use p256::pkcs8::DecodePrivateKey;
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let key_pem = key.serialize_pem();
    let params = rcgen::CertificateParams::new(vec![node_name.to_string()]).unwrap();
    let cert = params.self_signed(&key).unwrap();
    let sk = p256::ecdsa::SigningKey::from_pkcs8_pem(&key_pem).unwrap();
    (cert.pem(), key_pem, *sk.verifying_key())
}

#[tokio::test]
async fn token_join_issues_generation_zero_and_persists() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::open(dir.path()).unwrap();
    let jm = TokenJoin::new(cp.mint_token());

    let cred = identity::enroll(
        &store,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &jm,
        "node-a",
    )
    .await
    .expect("token enrollment issues an identity");

    assert_eq!(cred.generation, 0);
    assert!(!cred.agent_id.is_empty());
    assert!(!cred.node_id.is_empty());
    let loaded = store.load().unwrap().expect("persisted");
    assert_eq!(loaded.agent_id, cred.agent_id);
    assert_eq!(loaded.node_id, cred.node_id);
    assert_eq!(loaded.generation, 0);
    assert!(!loaded.ca_chain_der.is_empty());
}

#[tokio::test]
async fn token_join_token_is_single_use() {
    let cp = MockCp::start().await;
    let token = cp.mint_token();

    let dir1 = tempfile::tempdir().unwrap();
    let store1 = IdentityStore::open(dir1.path()).unwrap();
    identity::enroll(
        &store1,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &TokenJoin::new(token.clone()),
        "node-1",
    )
    .await
    .expect("first enrollment succeeds");

    let dir2 = tempfile::tempdir().unwrap();
    let store2 = IdentityStore::open(dir2.path()).unwrap();
    let err = identity::enroll(
        &store2,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &TokenJoin::new(token),
        "node-2",
    )
    .await
    .expect_err("replayed join token must be rejected");
    assert!(matches!(err, identity::IdentityError::Rpc(_)));
}

#[tokio::test]
async fn oidc_join_verifies_workload_token_and_rejects_bad() {
    let cp = MockCp::start().await;
    cp.set_expected_oidc("good.workload.jwt");

    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::open(dir.path()).unwrap();
    let cred = identity::enroll(
        &store,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &OidcJoin::from_literal("good.workload.jwt"),
        "node-oidc",
    )
    .await
    .expect("valid workload token enrolls");
    assert_eq!(cred.generation, 0);

    let dir2 = tempfile::tempdir().unwrap();
    let store2 = IdentityStore::open(dir2.path()).unwrap();
    let err = identity::enroll(
        &store2,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &OidcJoin::from_literal("forged.workload.jwt"),
        "node-oidc-2",
    )
    .await
    .expect_err("a bad workload token must be rejected");
    assert!(matches!(err, identity::IdentityError::Rpc(_)));
}

#[tokio::test]
async fn mtls_join_accepts_preprovisioned_cert_with_pop() {
    let cp = MockCp::start().await;
    let (cert_pem, key_pem, vk) = operator_material("node-mtls");
    cp.set_operator_vk(vk);
    let jm = MtlsJoin::from_pem(cert_pem.as_bytes(), &key_pem).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::open(dir.path()).unwrap();
    let cred = identity::enroll(
        &store,
        &cp.channel_params(CT, RT),
        &cp.bootstrap_anchors(),
        &jm,
        "node-mtls",
    )
    .await
    .expect("mtls pre-provisioned enrollment succeeds");
    assert_eq!(cred.generation, 0);
}

#[tokio::test]
async fn renew_rotates_cert_and_increments_generation_on_disk() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);

    let c0 = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &TokenJoin::new(cp.mint_token()),
        "node-r",
    )
    .await
    .unwrap();
    let cert0 = c0.identity.cert_pem.clone();

    let c1 = identity::renew(&store, &params, &c0).await.expect("renew");
    assert_eq!(c1.generation, 1);
    assert_ne!(c1.identity.cert_pem, cert0, "the certificate rotated");
    // Persist-before-adopt: the on-disk generation is the new one.
    assert_eq!(store.load().unwrap().unwrap().generation, 1);
    assert_eq!(cp.recorded_generation(&c1.agent_id), Some(1));
}

#[tokio::test]
async fn clone_detection_forks_counter_and_locks_both_copies() {
    let cp = MockCp::start().await;
    let params = cp.channel_params(CT, RT);

    // The legitimate agent enrolls (gen 0) and persists to dir1.
    let dir1 = tempfile::tempdir().unwrap();
    let store1 = IdentityStore::open(dir1.path()).unwrap();
    let c0 = identity::enroll(
        &store1,
        &params,
        &cp.bootstrap_anchors(),
        &TokenJoin::new(cp.mint_token()),
        "node-clone",
    )
    .await
    .unwrap();

    let dir2 = tempfile::tempdir().unwrap();
    {
        let name = "identity.json";
        std::fs::copy(dir1.path().join(name), dir2.path().join(name)).unwrap();
    }
    let store2 = IdentityStore::open(dir2.path()).unwrap();
    let clone_cred = store2.load().unwrap().expect("cloned credential");
    assert_eq!(clone_cred.generation, 0);

    let c1 = identity::renew(&store1, &params, &c0)
        .await
        .expect("legit renew");
    assert_eq!(c1.generation, 1);

    let clone_err = identity::renew(&store2, &params, &clone_cred)
        .await
        .expect_err("the stale clone must be detected");
    assert!(
        matches!(clone_err, identity::IdentityError::Rpc(_)),
        "clone renewal is refused by the CP (auto-locked): {clone_err:?}"
    );
    assert!(
        cp.is_node_locked("node-clone"),
        "the node is auto-locked (no auto-clear)"
    );

    let legit_err = identity::renew(&store1, &params, &c1)
        .await
        .expect_err("the now-locked identity must fail closed for the legit copy too");
    assert!(matches!(legit_err, identity::IdentityError::Rpc(_)));
}

#[tokio::test]
async fn persist_before_adopt_survives_crash_between_persist_and_adopt() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();

    let want = {
        let store = IdentityStore::open(dir.path()).unwrap();
        let cred = identity::enroll(
            &store,
            &cp.channel_params(CT, RT),
            &cp.bootstrap_anchors(),
            &TokenJoin::new(cp.mint_token()),
            "node-crash",
        )
        .await
        .unwrap();
        (cred.agent_id.clone(), cred.generation)
    };

    let store2 = IdentityStore::open(dir.path()).unwrap();
    let loaded = store2
        .load()
        .unwrap()
        .expect("credential recovered after crash");
    assert_eq!(loaded.agent_id, want.0);
    assert_eq!(loaded.generation, want.1);
}

#[tokio::test]
async fn locked_node_fails_closed_for_renew_and_reenroll() {
    let cp = MockCp::start().await;
    let params = cp.channel_params(CT, RT);
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::open(dir.path()).unwrap();

    let c0 = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &TokenJoin::new(cp.mint_token()),
        "node-locked",
    )
    .await
    .unwrap();

    // An incident lock on the node (§8.1): revocation via lock is not bypassable.
    cp.lock_node("node-locked");

    let renew_err = identity::renew(&store, &params, &c0)
        .await
        .expect_err("a locked identity must be refused for renewal");
    assert!(matches!(renew_err, identity::IdentityError::Rpc(_)));

    let dir2 = tempfile::tempdir().unwrap();
    let store2 = IdentityStore::open(dir2.path()).unwrap();
    let reenroll_err = identity::enroll(
        &store2,
        &params,
        &cp.bootstrap_anchors(),
        &TokenJoin::new(cp.mint_token()),
        "node-locked",
    )
    .await
    .expect_err("re-join of a locked node must be refused");
    assert!(matches!(reenroll_err, identity::IdentityError::Rpc(_)));
}

// Regression: a lost/late RenewAgentIdentity response makes the renew-ahead
// loop retry with the SAME stale generation. The CP's fix (a replay receipt keyed
// on the CSR public key) only helps if the Agent's retry presents the SAME CSR —
// a fresh keypair per attempt (the pre-fix behavior) makes the retry
// indistinguishable from a genuine clone and defeats the CP fix entirely. Assert
// the retry after a Transient failure reuses the identical CSR, and that renewal
// still succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renew_ahead_retry_reuses_the_same_csr_after_a_transient_failure() {
    let cp = MockCp::start().await;
    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);

    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &TokenJoin::new(cp.mint_token()),
        "node-retry",
    )
    .await
    .unwrap();
    let agent_id = cred.agent_id.clone();

    cp.fail_next_renew(&agent_id); // the FIRST renew attempt: simulated transient outage

    let renew = RenewAhead::new(
        store,
        RenewAheadConfig {
            renew_ahead_fraction: 0.0, // renew immediately
            renew_jitter_fraction: 0.0,
            retry_backoff: Duration::from_millis(50),
            channel: params,
        },
        cred,
    );

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let loop_task = tokio::spawn(renew.run(Box::pin(async move {
        let _ = stop_rx.await;
    })));

    // Real time: enough for the failed attempt, the ~50ms backoff, and the retry.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let _ = stop_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;

    let csrs = cp.recorded_renew_csrs(&agent_id);
    assert!(
        csrs.len() >= 2,
        "expected a failed attempt followed by a retry, got {} renew call(s)",
        csrs.len()
    );
    assert_eq!(
        csrs[0], csrs[1],
        "a retry after a Transient failure must present the IDENTICAL CSR: a fresh \
         keypair per attempt defeats the CP's CSR-keyed replay receipt"
    );
    assert_eq!(
        cp.recorded_generation(&agent_id),
        Some(1),
        "the retry must still land the renewal at generation 1"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn renew_loop_does_not_storm_when_the_cp_issues_expired_certs() {
    let cp = MockCp::start().await;
    cp.set_cert_ttl(Duration::ZERO); // every issued cert lands already-expired

    let dir = tempfile::tempdir().unwrap();
    let store = IdentityStore::open(dir.path()).unwrap();
    let params = cp.channel_params(CT, RT);
    let cred = identity::enroll(
        &store,
        &params,
        &cp.bootstrap_anchors(),
        &TokenJoin::new(cp.mint_token()),
        "node-storm",
    )
    .await
    .expect("enrollment (already-expired cert)");
    let agent_id = cred.agent_id.clone();

    let renew = RenewAhead::new(
        store,
        RenewAheadConfig {
            renew_ahead_fraction: 2.0 / 3.0,
            renew_jitter_fraction: 0.1,
            retry_backoff: Duration::from_secs(1),
            channel: params,
        },
        cred,
    );

    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let loop_task = tokio::spawn(renew.run(Box::pin(async move {
        let _ = stop_rx.await;
    })));

    // Real time: with the floor the loop renews ~once then sleeps 60s. A storm would
    // rack up hundreds of generations over this window.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let _ = stop_tx.send(());
    let _ = tokio::time::timeout(Duration::from_secs(5), loop_task).await;

    let gen = cp.recorded_generation(&agent_id).expect("agent is known");
    assert!(
        (1..=5).contains(&gen),
        "the renew loop must renew a bounded number of times under the storm \
         condition (got generation {gen}); the floor prevents a back-to-back storm"
    );
}
