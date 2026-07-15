//! Process supervision: the identity loop and the connectivity role, concurrently.
//!
//! The renew-ahead loop (S12) is **spawned, never awaited inline** (contract §7).
//! That is a availability requirement, not a style preference: a terminal identity
//! outcome — clone detection (`GenerationMismatch`) or a repair-needed rejection —
//! must stop the Agent taking *new* work and exit with its distinct code, but it
//! **must not tear down live spliced sessions**. Someone's `ssh` session is a real
//! user doing real work; the credential that authorised it was valid when the
//! session started, and the Gateway re-evaluates authorization per-channel anyway
//! (S10). So a terminal outcome triggers a **bounded drain**, not a kill.
//!
//! The S12 exit-code contract is preserved exactly: 0 clean, 3 clone, 4 repair.

use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;

use crate::gateway::GatewayClient;
use crate::identity::{RenewAhead, RenewOutcome};

/// Grace beyond the client's own drain deadline before the supervisor stops waiting
/// on it. The client bounds the drain itself; this is the belt-and-braces outer
/// bound so a wedged task can never hold the process open indefinitely.
const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Run the renew-ahead loop and (optionally) the Gateway control channel until
/// `shutdown` resolves or the identity loop stops terminally.
///
/// Returns the [`RenewOutcome`] the caller turns into the process exit code.
pub async fn run(
    renew: RenewAhead,
    gateway: Option<GatewayClient>,
    drain_deadline: Duration,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> RenewOutcome {
    let (stop_tx, stop_rx) = watch::channel(false);

    let gateway_task = gateway.map(|client| tokio::spawn(client.run(stop_rx)));

    // SPAWNED, not awaited inline: the control channel and every live splice run
    // concurrently with the identity loop and outlive its terminal outcomes.
    let renew_task = tokio::spawn(renew.run(Box::pin(shutdown)));

    let outcome = match renew_task.await {
        Ok(outcome) => outcome,
        Err(e) => {
            // The identity loop panicked. Treat it as repair-needed rather than a
            // clean exit: an orchestrator must not read this as success.
            tracing::error!(error = %e, "renew-ahead loop panicked");
            RenewOutcome::RepairNeeded
        }
    };

    if !matches!(outcome, RenewOutcome::Shutdown) {
        tracing::error!(
            outcome = ?outcome,
            drain_deadline_secs = drain_deadline.as_secs(),
            "terminal identity outcome — refusing new sessions and draining live ones \
             (live sessions are NOT torn down; see RUNBOOK.md)"
        );
    }

    // Stop taking new work, then let the client drain what is already live.
    let _ = stop_tx.send(true);
    if let Some(task) = gateway_task {
        if tokio::time::timeout(drain_deadline + DRAIN_GRACE, task)
            .await
            .is_err()
        {
            tracing::warn!("gateway task did not stop within the drain bound");
        }
    }

    outcome
}
