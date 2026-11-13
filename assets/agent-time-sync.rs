// SPDX-License-Identifier: Apache-2.0
//! Container admission gate for authenticated time.
//!
//! Asks chronyd over its root-only socket and latches the answer in memory;
//! files under `/run` could be planted by the host.

use anyhow::{bail, Context, Result};
use std::future::Future;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::time::{sleep, timeout, Duration};

const CHRONYC: &str = "/usr/bin/chronyc";
const CONTROL_SOCKET: &str = "/run/chrony/chronyd.sock";
// Max remaining clock correction in seconds; matches podvm-time-sync.
const MAX_CORRECTION: &str = "0.1";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_INTERVAL: Duration = Duration::from_millis(250);
// No answer means chronyd isn't up yet; also bounds the reaper-lock hold.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Boot-scoped; set only by a successful chronyd answer.
pub struct Admission(AtomicBool);

static ADMISSION: Admission = Admission(AtomicBool::new(false));

// Do not hold sandbox/process locks: networking and DNS must remain available.
pub async fn wait() -> Result<()> {
    wait_for(&ADMISSION, || synchronized(CHRONYC), STARTUP_TIMEOUT).await
}

/// Exit 0 = synchronized; other status or timeout = not yet; unrunnable
/// client = error.
async fn synchronized(client: &str) -> Result<bool> {
    // Keep the agent's SIGCHLD reaper from stealing the exit status.
    let _waiter = rustjail::container::WAIT_PID_LOCKER.lock().await;
    let mut command = tokio::process::Command::new(client);
    command
        .args(["-h", CONTROL_SOCKET, "waitsync", "1", MAX_CORRECTION, "0", "1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    match timeout(PROBE_TIMEOUT, command.status()).await {
        Ok(status) => Ok(status
            .with_context(|| format!("cannot query chronyd through {client}"))?
            .success()),
        Err(_) => Ok(false),
    }
}

async fn wait_for<F, Fut>(admission: &Admission, probe: F, limit: Duration) -> Result<()>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<bool>>,
{
    // Latched until reboot.
    if admission.0.load(Ordering::Acquire) {
        return Ok(());
    }
    let result = timeout(limit, async {
        loop {
            if probe().await? {
                admission.0.store(true, Ordering::Release);
                return Ok(());
            }
            sleep(PROBE_INTERVAL).await;
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => bail!(
            "initial authenticated time synchronization not ready after {} seconds",
            limit.as_secs()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    fn fresh() -> Admission {
        Admission(AtomicBool::new(false))
    }

    #[tokio::test]
    async fn delayed_synchronization_admits_and_latches() {
        let admission = fresh();
        let calls = Arc::new(AtomicUsize::new(0));
        let probe = {
            let calls = calls.clone();
            move || {
                let calls = calls.clone();
                async move { Ok::<bool, anyhow::Error>(calls.fetch_add(1, Ordering::SeqCst) >= 2) }
            }
        };
        wait_for(&admission, probe, Duration::from_secs(5)).await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        // Later failures don't revoke admission.
        wait_for(&admission, || async { Ok::<bool, anyhow::Error>(false) }, Duration::from_millis(20))
            .await
            .unwrap();
        wait_for(
            &admission,
            || async { Err::<bool, anyhow::Error>(anyhow::anyhow!("daemon gone")) },
            Duration::from_millis(20),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn unsynchronized_fails_closed_and_can_recover() {
        let admission = fresh();
        let error = wait_for(&admission, || async { Ok::<bool, anyhow::Error>(false) }, Duration::from_millis(20))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not ready"), "{:#}", error);
        assert!(!admission.0.load(Ordering::SeqCst));
        let error = wait_for(
            &admission,
            || async { Err::<bool, anyhow::Error>(anyhow::anyhow!("no daemon")) },
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("no daemon"), "{:#}", error);
        assert!(!admission.0.load(Ordering::SeqCst));
        wait_for(&admission, || async { Ok::<bool, anyhow::Error>(true) }, Duration::from_millis(20))
            .await
            .unwrap();
        assert!(admission.0.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn client_exit_status_is_the_only_signal() {
        assert!(synchronized("/nonexistent/chronyc").await.is_err());
        assert!(!synchronized("/bin/false").await.unwrap());
        assert!(synchronized("/bin/true").await.unwrap());
    }
}
