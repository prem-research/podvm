// SPDX-License-Identifier: Apache-2.0
//! Sandbox-wide model initialization, after request authorization and before jail mounts.

use anyhow::{anyhow, bail, Context, Result};
use oci_spec::runtime::Spec;
use serde::{Deserialize, Serialize};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const HELPER: &str = "/usr/local/bin/podvm-model-mount";
const TIMEOUT: Duration = Duration::from_secs(45);

struct ProcessGroup(i32);
impl Drop for ProcessGroup {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                libc::kill(-self.0, libc::SIGKILL);
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    root_hash: String,
    hash_offset: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Model {
    modelid: String,
    mount_path: String,
    parameters: Parameters,
}

#[derive(Serialize)]
struct ResolvedModel<'a> {
    #[serde(flatten)]
    model: &'a Model,
    input_path: PathBuf,
}

#[derive(Debug)]
enum Phase {
    Disabled,
    Pending,
    Ready,
    Failed(String),
}

#[derive(Debug)]
pub struct Gate {
    models: Vec<Model>,
    phase: Phase,
}

impl Default for Gate {
    fn default() -> Self {
        Self {
            models: Vec::new(),
            phase: Phase::Disabled,
        }
    }
}

pub fn parse(value: &str) -> Result<Vec<Model>> {
    let models: Vec<Model> = serde_json::from_str(value).context("invalid model-mounts.json")?;
    for (i, model) in models.iter().enumerate() {
        let path = &model.mount_path;
        if !path.starts_with("/models/")
            || path.contains('\0')
            || path
                .split('/')
                .skip(1)
                .any(|c| c.is_empty() || c == "." || c == "..")
        {
            bail!("model {i}: mount_path must be a normalized path under /models/");
        }
        let (name, revision) = model
            .modelid
            .rsplit_once('@')
            .ok_or_else(|| anyhow!("model {i}: modelid must be name@revision"))?;
        if name.is_empty()
            || revision.is_empty()
            || model
                .modelid
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            bail!("model {i}: invalid exact model identity");
        }
        let params = &model.parameters;
        if params.root_hash.len() != 64
            || !params
                .root_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("model {i}: root_hash must be 64 lowercase hexadecimal characters");
        }
        if params.hash_offset == 0
            || params.hash_offset % 4096 != 0
            || params.hash_offset > (1u64 << 62)
        {
            bail!("model {i}: invalid hash_offset");
        }
        for prev in &models[..i] {
            if path == &prev.mount_path
                || path.starts_with(&(prev.mount_path.clone() + "/"))
                || prev.mount_path.starts_with(&(path.clone() + "/"))
            {
                bail!("duplicate or overlapping model mount paths");
            }
        }
    }
    Ok(models)
}

fn infrastructure(spec: &Spec, cid: &str, sandbox_id: &str) -> bool {
    if cid != sandbox_id || sandbox_id.is_empty() {
        return false;
    }
    let Some(annotations) = spec.annotations() else {
        return false;
    };
    if annotations
        .get("io.katacontainers.pkg.oci.container_type")
        .map(String::as_str)
        != Some("pod_sandbox")
    {
        return false;
    }
    // Reject conflicting CRI classification rather than exempting a workload.
    for key in [
        "io.kubernetes.cri.container-type",
        "io.kubernetes.cri-o.ContainerType",
    ] {
        if let Some(value) = annotations.get(key) {
            if value != "sandbox" {
                return false;
            }
        }
    }
    true
}

fn resolve<'a>(
    models: &'a [Model],
    spec: &Spec,
    require_all: bool,
) -> Result<Vec<ResolvedModel<'a>>> {
    // An additional parent/child mount could hide verified files after rewriting.
    for mount in spec.mounts().as_deref().unwrap_or_default() {
        let dest = mount.destination().to_string_lossy();
        if dest.split('/').skip(1).any(|c| c == "." || c == "..") {
            bail!("non-normalized mount destination");
        }
        for model in models {
            if dest != model.mount_path
                && (dest == "/"
                    || dest.starts_with(&(model.mount_path.clone() + "/"))
                    || model.mount_path.starts_with(&(dest.to_string() + "/")))
            {
                bail!(
                    "mount at {dest} overlaps model destination {}",
                    model.mount_path
                );
            }
        }
    }
    let mut resolved = Vec::new();
    for model in models {
        let matches: Vec<_> = spec
            .mounts()
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter(|m| m.destination() == Path::new(&model.mount_path))
            .collect();
        if matches.is_empty() && !require_all {
            continue;
        }
        if matches.len() != 1 {
            bail!(
                "model {}: require exactly one mount at {}",
                model.modelid,
                model.mount_path
            );
        }
        let mount = matches[0];
        let options = mount.options().as_deref().unwrap_or_default();
        if mount.typ().as_deref() != Some("bind")
            || !options.iter().any(|o| o == "ro")
            || options
                .iter()
                .any(|o| matches!(o.as_str(), "rw" | "shared" | "rshared" | "slave" | "rslave"))
        {
            bail!(
                "model {}: require a read-only private file bind mount",
                model.modelid
            );
        }
        let input_path = mount
            .source()
            .clone()
            .ok_or_else(|| anyhow!("missing model input"))?;
        // Only resolve runtime-shared files, never guest rootfs/device paths.
        if !input_path.starts_with("/run/kata-containers/shared/containers")
            || input_path.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            bail!(
                "model {}: input is outside Kata's shared files",
                model.modelid
            );
        }
        resolved.push(ResolvedModel { model, input_path });
    }
    Ok(resolved)
}

fn rewrite(models: &[Model], spec: &mut Spec) {
    if let Some(mounts) = spec.mounts_mut() {
        for mount in mounts {
            if let Some(index) = models
                .iter()
                .position(|m| mount.destination() == Path::new(&m.mount_path))
            {
                mount.set_source(Some(PathBuf::from(format!(
                    "/run/modelwrap/mounts/{index}"
                ))));
                mount.set_options(Some(
                    ["bind", "rprivate", "ro", "nodev", "nosuid", "noexec"]
                        .iter()
                        .map(|s| s.to_string())
                        .collect(),
                ));
            }
        }
    }
}

async fn helper(operation: &str, input: &[u8]) -> Result<()> {
    let timeout = if operation == "cleanup" {
        Duration::from_secs(10)
    } else {
        TIMEOUT
    };
    helper_command(HELPER, operation, input, timeout).await
}

async fn helper_command(
    path: &str,
    operation: &str,
    input: &[u8],
    timeout: Duration,
) -> Result<()> {
    // SIGCHLD's generic reaper must not consume the helper's exit status.
    let _waiter = rustjail::container::WAIT_PID_LOCKER.lock().await;
    let mut command = tokio::process::Command::new(path);
    command
        .arg(operation)
        .stdin(Stdio::piped())
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().context("start model mount helper")?;
    let pid = child.id().ok_or_else(|| anyhow!("missing helper PID"))? as i32;
    let mut group = ProcessGroup(pid);
    let result = tokio::time::timeout(timeout, async {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("missing helper stdin"))?;
        stdin.write_all(input).await?;
        drop(stdin);
        let status = child.wait().await?;
        if !status.success() {
            bail!("model mount helper {operation} failed: {status}");
        }
        Ok(())
    })
    .await;
    match result {
        Ok(Ok(())) => {
            group.0 = 0;
            Ok(())
        }
        error => {
            // Stop the whole group, including veritysetup/mount, before rollback.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            // A task stuck in kernel I/O may not reap immediately after SIGKILL.
            // Keep the startup bound even in that case; the normal reaper takes
            // over once this helper releases WAIT_PID_LOCKER.
            let _ = tokio::time::timeout(Duration::from_secs(1), child.wait()).await;
            group.0 = 0;
            match error {
                Ok(Err(e)) => Err(e),
                Err(_) => Err(anyhow!("model mount helper {operation} timed out")),
                Ok(Ok(())) => unreachable!(),
            }
        }
    }
}

impl Gate {
    pub fn new(models: Vec<Model>) -> Self {
        let phase = if models.is_empty() {
            Phase::Disabled
        } else {
            Phase::Pending
        };
        Self { models, phase }
    }

    // Called under a dedicated mutex, never while holding the sandbox mutex.
    pub async fn prepare(&mut self, spec: &mut Spec, cid: &str, sandbox_id: &str) -> Result<()> {
        if matches!(self.phase, Phase::Disabled) {
            return Ok(());
        }
        if let Phase::Failed(message) = &self.phase {
            bail!("model mounts failed; recreate sandbox: {message}");
        }
        if infrastructure(spec, cid, sandbox_id) {
            // Infrastructure cannot carry model destinations or bypass their gate.
            if spec
                .mounts()
                .as_deref()
                .unwrap_or_default()
                .iter()
                .any(|mount| {
                    self.models
                        .iter()
                        .any(|m| mount.destination() == Path::new(&m.mount_path))
                })
            {
                bail!("infrastructure container cannot request model mounts");
            }
            return Ok(());
        }
        let pending = matches!(self.phase, Phase::Pending);
        if pending {
            self.phase = Phase::Failed("initialization interrupted".into());
        }
        let result = async {
            let resolved = resolve(&self.models, spec, pending)?;
            if pending {
                let input = serde_json::to_vec(&resolved)?;
                helper("mount", &input).await?;
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if let Err(e) = result {
            if pending {
                self.phase = Phase::Failed(format!("{e:#}"));
                if let Err(cleanup) = helper("cleanup", &[]).await {
                    return Err(e.context(format!("rollback failed: {cleanup:#}")));
                }
            }
            return Err(e);
        }
        self.phase = Phase::Ready;
        if pending {
            slog::info!(slog_scope::logger(), "model mounts ready"; "count" => self.models.len());
        }
        rewrite(&self.models, spec);
        Ok(())
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        if !matches!(self.phase, Phase::Disabled) {
            self.phase = Phase::Failed("sandbox destroyed".into());
            helper("cleanup", &[]).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oci_spec::runtime::{MountBuilder, SpecBuilder};
    use std::collections::HashMap;
    use std::os::unix::fs::PermissionsExt;

    fn config() -> String {
        format!(
            r#"[{{"modelid":"org/model@revision","mount_path":"/models/example","parameters":{{"root_hash":"{}","hash_offset":4096}}}}]"#,
            "ab".repeat(32)
        )
    }
    fn spec(destination: &str, source: &str, options: &[&str]) -> Spec {
        SpecBuilder::default()
            .mounts(vec![MountBuilder::default()
                .destination(destination)
                .typ("bind")
                .source(source)
                .options(options.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .build()
                .unwrap()])
            .build()
            .unwrap()
    }
    #[test]
    fn configuration_validation() {
        assert!(parse("[]").unwrap().is_empty());
        assert_eq!(parse(&config()).unwrap().len(), 1);
        for value in [
            "null".into(),
            "{}".into(),
            "[".into(),
            config().replace("4096", "0"),
            config().replace("4096", "4097"),
            config().replace("org/model@revision", "alias"),
            config().replace("/models/example", "/models/../etc"),
            config().replace("/models/example", "/models//example"),
            config().replace("/models/example", "/etc/example"),
            config().replace("abab", "ABAB"),
            config().replace("\"modelid\":", "\"unknown\":"),
        ] {
            assert!(parse(&value).is_err(), "{}", value);
        }
        let one = config();
        let entry = &one[1..one.len() - 1];
        assert!(parse(&format!("[{entry},{entry}]")).is_err());
        assert!(parse(&format!(
            "[{entry},{}]",
            entry.replace("/models/example", "/models/example/child")
        ))
        .is_err());
    }
    #[test]
    fn resolve_and_rewrite_only_configured_mounts() {
        let models = parse(&config()).unwrap();
        let mut spec = spec(
            "/models/example",
            "/run/kata-containers/shared/containers/id-random-example",
            &["rbind", "rprivate", "ro"],
        );
        let resolved = resolve(&models, &spec, true).unwrap();
        assert_eq!(resolved.len(), 1);
        assert!(serde_json::to_string(&resolved)
            .unwrap()
            .contains("input_path"));
        rewrite(&models, &mut spec);
        let mount = &spec.mounts().as_ref().unwrap()[0];
        assert_eq!(
            mount.source().as_deref(),
            Some(Path::new("/run/modelwrap/mounts/0"))
        );
        assert_eq!(mount.destination(), Path::new("/models/example"));
        assert!(mount
            .options()
            .as_ref()
            .unwrap()
            .iter()
            .any(|o| o == "noexec"));
    }
    #[test]
    fn missing_writable_and_untrusted_sources_rejected() {
        let models = parse(&config()).unwrap();
        for (dest, source, options) in [
            (
                "/models/missing",
                "/run/kata-containers/shared/containers/input",
                vec!["ro"],
            ),
            (
                "/models/example",
                "/run/kata-containers/shared/containers/input",
                vec!["rw"],
            ),
            (
                "/models/example",
                "/run/kata-containers/shared/containers/input",
                vec!["ro", "rshared"],
            ),
            ("/models/example", "/etc/input", vec!["ro"]),
            (
                "/models/example",
                "/run/kata-containers/shared/containers/../input",
                vec!["ro"],
            ),
        ] {
            assert!(resolve(&models, &spec(dest, source, &options), true).is_err());
        }
        assert!(resolve(&models, &Spec::default(), false)
            .unwrap()
            .is_empty());
    }
    #[cfg(feature = "agent-policy")]
    #[tokio::test]
    async fn genpolicy_authorizes_original_mount_and_rejects_substitutions() {
        use kata_agent_policy::policy::AgentPolicy;
        let mut policy = AgentPolicy::new();
        let mut rules = include_str!("../../tools/genpolicy/rules.rego").to_string();
        rules.push_str(
            r#"
policy_data := {"common": {"sfprefix": "unused", "cpath": "unused"}}
default ModelMountCheck := false
ModelMountCheck := true if { check_mount(input.expected, input.actual, "bundle", "sandbox") }
"#,
        );
        policy.set_policy(&rules).await.unwrap();
        let expected = serde_json::json!({
            "destination": "/models/example", "type_": "bind", "options": ["rbind", "rprivate", "ro"],
            "source": "^/run/kata-containers/shared/containers/$(bundle-id)-[a-z0-9]{16}-example$"
        });
        let mut actual = expected.clone();
        actual["source"] = serde_json::json!(
            "/run/kata-containers/shared/containers/bundle-0123456789abcdef-example"
        );
        let request = |actual: &serde_json::Value| {
            serde_json::json!({"expected": expected, "actual": actual}).to_string()
        };
        assert!(
            policy
                .allow_request("ModelMountCheck", &request(&actual))
                .await
                .unwrap()
                .0
        );
        for (field, value) in [
            ("source", serde_json::json!("/etc/untrusted")),
            ("source", serde_json::json!("/run/modelwrap/mounts/0")),
            ("destination", serde_json::json!("/models/other")),
            ("options", serde_json::json!(["rbind", "rprivate", "rw"])),
        ] {
            let mut changed = actual.clone();
            changed[field] = value;
            assert!(
                !policy
                    .allow_request("ModelMountCheck", &request(&changed))
                    .await
                    .unwrap()
                    .0
            );
        }
    }

    #[test]
    fn shadowing_mounts_are_rejected() {
        let models = parse(&config()).unwrap();
        for path in [
            "/models",
            "/models/example/weights",
            "/",
            "/models/example/../other",
        ] {
            assert!(resolve(
                &models,
                &spec(
                    path,
                    "/run/kata-containers/shared/containers/input",
                    &["ro"]
                ),
                false
            )
            .is_err());
        }
    }

    #[test]
    fn infrastructure_requires_matching_identity() {
        let mut spec = Spec::default();
        spec.set_annotations(Some(HashMap::from([(
            "io.katacontainers.pkg.oci.container_type".into(),
            "pod_sandbox".into(),
        )])));
        assert!(infrastructure(&spec, "sandbox", "sandbox"));
        assert!(!infrastructure(&spec, "workload", "sandbox"));
        spec.annotations_mut().as_mut().unwrap().insert(
            "io.kubernetes.cri.container-type".into(),
            "container".into(),
        );
        assert!(!infrastructure(&spec, "sandbox", "sandbox"));
    }
    #[tokio::test]
    async fn ready_reuses_mounts_and_disabled_preserves_spec() {
        let mut request = spec(
            "/models/example",
            "/run/kata-containers/shared/containers/new-input",
            &["ro"],
        );
        Gate::default()
            .prepare(&mut request, "app", "sandbox")
            .await
            .unwrap();
        assert!(request.mounts().as_ref().unwrap()[0]
            .source()
            .as_ref()
            .unwrap()
            .ends_with("new-input"));
        let mut gate = Gate::new(parse(&config()).unwrap());
        gate.phase = Phase::Ready;
        gate.prepare(&mut request, "app", "sandbox").await.unwrap();
        assert!(request.mounts().as_ref().unwrap()[0]
            .source()
            .as_ref()
            .unwrap()
            .ends_with("mounts/0"));
        gate.prepare(&mut Spec::default(), "other-app", "sandbox")
            .await
            .unwrap();
        gate.phase = Phase::Failed("previous error".into());
        assert!(gate
            .prepare(&mut Spec::default(), "other-app", "sandbox")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn first_workload_failure_is_latched_and_infrastructure_preserves_pending() {
        let mut gate = Gate::new(parse(&config()).unwrap());
        let mut pause = Spec::default();
        pause.set_annotations(Some(HashMap::from([(
            "io.katacontainers.pkg.oci.container_type".into(),
            "pod_sandbox".into(),
        )])));
        gate.prepare(&mut pause, "sandbox", "sandbox")
            .await
            .unwrap();
        assert!(matches!(gate.phase, Phase::Pending));
        let error = gate
            .prepare(&mut Spec::default(), "init", "sandbox")
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("require exactly one mount"));
        let mut request = spec(
            "/models/example",
            "/run/kata-containers/shared/containers/input",
            &["ro"],
        );
        let error = gate
            .prepare(&mut request, "app", "sandbox")
            .await
            .unwrap_err();
        assert!(error.to_string().contains("recreate sandbox"));
        assert_eq!(
            request.mounts().as_ref().unwrap()[0].source().as_deref(),
            Some(Path::new("/run/kata-containers/shared/containers/input"))
        );
    }

    #[tokio::test]
    async fn timeout_and_cancellation_stop_helper_descendants() {
        for cancel in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let script = dir.path().join("helper");
            let marker = dir.path().join("survived");
            let started = dir.path().join("started");
            std::fs::write(
                &script,
                format!(
                    "#!/bin/sh\n(sleep 1; touch '{}') &\ntouch '{}'\nwait\n",
                    marker.display(),
                    started.display()
                ),
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            let path = script.to_string_lossy().into_owned();
            let timeout = if cancel {
                Duration::from_secs(5)
            } else {
                Duration::from_millis(200)
            };
            let task =
                tokio::spawn(async move { helper_command(&path, "mount", &[], timeout).await });
            tokio::time::timeout(Duration::from_secs(2), async {
                while !started.exists() {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            if cancel {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                assert!(task
                    .await
                    .unwrap()
                    .unwrap_err()
                    .to_string()
                    .contains("timed out"));
            }
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert!(!marker.exists(), "helper descendant survived termination");
        }
    }
}
