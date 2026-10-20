// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use std::path::Path;
use tokio::time::{sleep, timeout, Duration};

const READY: &str = "/run/podvm-time/ready";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

// Readiness is boot-scoped, published only by the root-owned time supervisor.
// Do not hold sandbox/process locks: networking and DNS must remain available.
pub async fn wait() -> Result<()> {
    wait_for(Path::new(READY), STARTUP_TIMEOUT).await
}

async fn wait_for(path: &Path, limit: Duration) -> Result<()> {
    let result = timeout(limit, async {
        loop {
            match tokio::fs::symlink_metadata(path).await {
                Ok(metadata) if metadata.is_file() => return Ok(()),
                Ok(_) => bail!("invalid PodVM time synchronization readiness state"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    match result {
        Ok(result) => result,
        Err(_) => bail!("initial authenticated time synchronization not ready after 30 seconds"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delayed_readiness_and_later_requests() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ready");
        let publisher = async {
            sleep(Duration::from_millis(20)).await;
            tokio::fs::write(&path, b"").await.unwrap();
        };
        let (result, _) = tokio::join!(wait_for(&path, Duration::from_secs(1)), publisher);
        result.unwrap();
        wait_for(&path, Duration::from_millis(20)).await.unwrap();
    }

    #[tokio::test]
    async fn unavailable_source_fails_closed_and_can_recover() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ready");
        assert!(wait_for(&path, Duration::from_millis(20)).await.is_err());
        tokio::fs::write(&path, b"").await.unwrap();
        wait_for(&path, Duration::from_millis(20)).await.unwrap();
        assert!(wait_for(directory.path(), Duration::from_millis(20))
            .await
            .is_err());
    }
}
