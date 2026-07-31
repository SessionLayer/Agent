//! Process supervision: the identity loop and the connectivity role, concurrently.
//!
//! The renew-ahead loop is **spawned, never awaited inline**. A terminal identity
//! outcome must stop the Agent taking new work and exit with its distinct code, but
//! must not tear down live spliced sessions. The credential that authorised a
//! session was valid when it started, and the Gateway re-evaluates authorization
//! per-channel anyway. So a terminal outcome triggers a **bounded drain**, not a kill.
//!
//! Exit codes: 0 clean, 3 clone-detection, 4 repair-needed.

use std::future::Future;
use std::time::Duration;

use tokio::sync::watch;

use crate::gateway::GatewayClient;
use crate::identity::{RenewAhead, RenewOutcome};

const DRAIN_GRACE: Duration = Duration::from_secs(5);

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
            tracing::error!(error = %e, "renew-ahead loop panicked");
            RenewOutcome::RepairNeeded
        }
    };

    if !matches!(outcome, RenewOutcome::Shutdown) {
        tracing::error!(
            outcome = ?outcome,
            drain_deadline_secs = drain_deadline.as_secs(),
            "terminal identity outcome — refusing new sessions and draining live ones \
             (live sessions are NOT torn down; see the Agent runbook, \
             docs/operations/agent-runbook.md in the SessionLayer/Documentation repo)"
        );
    }

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
