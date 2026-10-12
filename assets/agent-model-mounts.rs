// SPDX-License-Identifier: Apache-2.0
//! Per-container verification of authorized raw block volumes before jail mounts.

use anyhow::{anyhow, bail, Context, Result};
use kata_types::device::{
    DRIVER_BLK_MMIO_TYPE, DRIVER_BLK_PCI_TYPE, DRIVER_NVDIMM_TYPE, DRIVER_SCSI_TYPE,
};
use oci_spec::runtime::Spec;
use protocols::agent::Storage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
pub struct Model {
    modelid: String,
    mount_path: String,
    info: String,
}

#[derive(Serialize)]
pub struct ResolvedModel {
    #[serde(flatten)]
    model: Model,
    input_path: PathBuf,
}

#[derive(Debug, Default)]
pub struct Gate {
    models: Vec<Model>,
    containers: BTreeSet<String>,
}

// A bounded digest prevents IDs from contributing path separators or aliases.
fn state_dir(cid: &str) -> PathBuf {
    let key: String = Sha256::digest(cid.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    PathBuf::from("/run/modelwrap/containers").join(key)
}

fn readonly_bind(typ: &str, options: &[String]) -> bool {
    typ == "bind"
        && options.iter().any(|o| o == "ro")
        && options.iter().any(|o| o == "bind" || o == "rbind")
        && !options.iter().any(|o| {
            matches!(
                o.as_str(),
                "rw" | "shared" | "rshared" | "slave" | "rslave" | "unbindable" | "runbindable"
            )
        })
}

fn block_driver(driver: &str) -> bool {
    matches!(
        driver,
        DRIVER_BLK_PCI_TYPE | DRIVER_BLK_MMIO_TYPE | DRIVER_SCSI_TYPE | DRIVER_NVDIMM_TYPE
    )
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
        // Match modelwrap::ParseRef's rootHash_hashOffset_uuid grammar.
        // All verification inputs come from initdata, not the pack superblock.
        let parts: Vec<&str> = model.info.split('_').collect();
        if parts.len() != 3 {
            bail!("model {i}: info must be ROOTHASH_OFFSET_VERITYUUID");
        }
        let (root_hash, offset, uuid) = (parts[0], parts[1], parts[2]);
        if root_hash.len() != 64
            || !root_hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("model {i}: root_hash must be 64 lowercase hexadecimal characters");
        }
        if offset.is_empty() || !offset.bytes().all(|b| b.is_ascii_digit()) {
            bail!("model {i}: invalid hash_offset in info");
        }
        let hash_offset: u64 = offset.parse().context("invalid hash_offset in info")?;
        if hash_offset == 0 || hash_offset % 4096 != 0 || hash_offset > (1u64 << 62) {
            bail!("model {i}: invalid hash_offset");
        }
        if uuid.len() != 36
            || !uuid.bytes().enumerate().all(|(pos, b)| {
                if matches!(pos, 8 | 13 | 18 | 23) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
        {
            bail!("model {i}: invalid verity UUID in info");
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

fn resolve(models: &[Model], spec: &Spec, storages: &[Storage]) -> Result<Vec<ResolvedModel>> {
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
        if matches.is_empty() {
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
        if !readonly_bind(mount.typ().as_deref().unwrap_or_default(), options) {
            bail!(
                "model {}: require a read-only private block bind mount",
                model.modelid
            );
        }
        let input_path = mount
            .source()
            .clone()
            .ok_or_else(|| anyhow!("missing model input"))?;
        if !input_path.is_absolute()
            || input_path.components().any(|c| {
                !matches!(
                    c,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
        {
            bail!("model {}: invalid block input path", model.modelid);
        }
        let records: Vec<_> = storages
            .iter()
            .filter(|s| Path::new(&s.mount_point) == input_path)
            .collect();
        if records.len() != 1 {
            bail!(
                "model {}: require exactly one corresponding block storage",
                model.modelid
            );
        }
        let storage = records[0];
        if !block_driver(&storage.driver)
            || storage.source.is_empty()
            || !readonly_bind(&storage.fstype, &storage.options)
            || !storage.driver_options.is_empty()
            || storage.fs_group.is_some()
        {
            bail!(
                "model {}: require raw read-only block storage",
                model.modelid
            );
        }
        resolved.push(ResolvedModel {
            model: model.clone(),
            input_path,
        });
    }
    Ok(resolved)
}

fn rewrite(models: &[ResolvedModel], spec: &mut Spec, dir: &Path) {
    if let Some(mounts) = spec.mounts_mut() {
        for mount in mounts {
            if let Some(index) = models
                .iter()
                .position(|m| mount.destination() == Path::new(&m.model.mount_path))
            {
                mount.set_source(Some(dir.join("mounts").join(index.to_string())));
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

async fn helper(operation: &str, dir: &Path, input: &[u8]) -> Result<()> {
    let timeout = if operation == "cleanup" {
        Duration::from_secs(10)
    } else {
        TIMEOUT
    };
    helper_command(HELPER, operation, dir, input, timeout).await
}

async fn helper_command(
    path: &str,
    operation: &str,
    dir: &Path,
    input: &[u8],
    timeout: Duration,
) -> Result<()> {
    // SIGCHLD's generic reaper must not consume the helper's exit status.
    let _waiter = rustjail::container::WAIT_PID_LOCKER.lock().await;
    let mut command = tokio::process::Command::new(path);
    command
        .arg(operation)
        .arg(dir)
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
        Self {
            models,
            containers: BTreeSet::new(),
        }
    }

    // Validate the original policy-authorized request before add_storages.
    pub fn validate(
        &self,
        spec: &Spec,
        storages: &[Storage],
        cid: &str,
        sandbox_id: &str,
    ) -> Result<Vec<ResolvedModel>> {
        if self.models.is_empty() {
            return Ok(Vec::new());
        }
        if infrastructure(spec, cid, sandbox_id) {
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
            return Ok(Vec::new());
        }
        resolve(&self.models, spec, storages)
    }

    pub async fn prepare(
        &mut self,
        spec: &mut Spec,
        resolved: &[ResolvedModel],
        cid: &str,
    ) -> Result<()> {
        if resolved.is_empty() {
            return Ok(());
        }
        if !self.containers.insert(cid.to_string()) {
            bail!("existing container model state; refusing to overwrite");
        }
        let dir = state_dir(cid);
        let result = helper("mount", &dir, &serde_json::to_vec(resolved)?).await;
        if let Err(e) = result {
            if let Err(cleanup) = self.cleanup_container(cid).await {
                return Err(e.context(format!("rollback failed: {cleanup:#}")));
            }
            return Err(e);
        }
        rewrite(resolved, spec, &dir);
        slog::info!(slog_scope::logger(), "model mounts ready"; "container" => cid, "count" => resolved.len());
        Ok(())
    }

    // Called after workload destruction and before removing Kata storage.
    // Keep the ID on failure so subsequent cleanup attempts can retry.
    pub async fn cleanup_container(&mut self, cid: &str) -> Result<()> {
        if self.containers.contains(cid) {
            helper("cleanup", &state_dir(cid), &[]).await?;
            self.containers.remove(cid);
            slog::info!(slog_scope::logger(), "model mounts cleaned"; "container" => cid);
        }
        Ok(())
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        for cid in self.containers.clone() {
            self.cleanup_container(&cid).await?;
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
            r#"[{{"modelid":"org/model@revision","mount_path":"/models/example","info":"{}_4096_01234567-89ab-cdef-0123-456789abcdef"}}]"#,
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
            config().replace("4096", "4611686018427392000"),
            config().replace("4096", "18446744073709551616"),
            config().replace("4096", "+4096"),
            config().replace("4096", "-4096"),
            config().replace("4096", "4096.0"),
            config().replace("_4096_", "_"),
            config().replace("_4096_", "_4096_extra_"),
            config().replace("89ab-cdef", "89AB-CDEF"),
            config().replace("89ab-cdef", "89ab_cdef"),
            config().replace("89ab-cdef", "89ag-cdef"),
            config().replace("01234567-89ab-cdef-0123-456789abcdef", "bad"),
            config().replace("abcdef\"", "abcdef \""),
            config().replace("\"info\":", "\"parameters\":"),
            format!(
                r#"[{{"modelid":"org/model@revision","mount_path":"/models/example","parameters":{{"root_hash":"{}","hash_offset":4096}}}}]"#,
                "ab".repeat(32)
            ),
            config().replace(
                &format!(
                    "\"{}_4096_01234567-89ab-cdef-0123-456789abcdef\"",
                    "ab".repeat(32)
                ),
                "null",
            ),
            r#"[{"modelid":"org/model@revision","mount_path":"/models/example"}]"#.into(),
            config().replace("org/model@revision", "alias"),
            config().replace("/models/example", "/models/../etc"),
            config().replace("/models/example", "/models//example"),
            config().replace("/models/example", "/etc/example"),
            config().replace("abab", "ABAB"),
            config().replace("\"modelid\":", "\"unknown\":"),
        ] {
            assert!(parse(&value).is_err(), "{}", value);
        }
        for offset in ["0004096", "4611686018427387904"] {
            assert!(parse(&config().replace("4096", offset)).is_ok());
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
    fn storage(driver: &str) -> Storage {
        Storage {
            driver: driver.into(),
            source: "transport-address".into(),
            mount_point: "/resolved/raw-input".into(),
            fstype: "bind".into(),
            options: vec!["bind".into(), "ro".into()],
            ..Default::default()
        }
    }

    #[test]
    fn block_provenance_subsets_and_rewrite() {
        let models = parse(&config()).unwrap();
        for driver in [
            DRIVER_SCSI_TYPE,
            DRIVER_BLK_PCI_TYPE,
            DRIVER_BLK_MMIO_TYPE,
            DRIVER_NVDIMM_TYPE,
        ] {
            let mut spec = spec(
                "/models/example",
                "/resolved/raw-input",
                &["rbind", "rprivate", "ro"],
            );
            let resolved = resolve(&models, &spec, &[storage(driver)]).unwrap();
            assert_eq!(resolved.len(), 1);
            assert_eq!(
                serde_json::to_value(&resolved).unwrap()[0]["info"],
                models[0].info
            );
            rewrite(&resolved, &mut spec, &state_dir("app"));
            assert_eq!(
                spec.mounts().as_ref().unwrap()[0]
                    .source()
                    .as_ref()
                    .unwrap(),
                &state_dir("app").join("mounts/0")
            );
        }
        assert!(resolve(&models, &Spec::default(), &[]).unwrap().is_empty());
        let gate = Gate::new(models);
        assert!(gate
            .validate(&Spec::default(), &[], "init", "sandbox")
            .unwrap()
            .is_empty());
        assert_ne!(state_dir("app"), state_dir("app2"));
        assert_ne!(state_dir("../app"), state_dir("app"));
    }

    #[test]
    fn rejects_unproven_writable_or_filesystem_inputs() {
        let models = parse(&config()).unwrap();
        let request = spec("/models/example", "/resolved/raw-input", &["bind", "ro"]);
        assert!(resolve(&models, &request, &[]).is_err());
        assert!(resolve(
            &models,
            &request,
            &[storage(DRIVER_SCSI_TYPE), storage(DRIVER_SCSI_TYPE)]
        )
        .is_err());
        for change in 0..7 {
            let mut record = storage(DRIVER_SCSI_TYPE);
            match change {
                0 => record.driver = "local".into(),
                1 => record.fstype = "erofs".into(),
                2 => record.options.push("rw".into()),
                3 => record.driver_options.push("create_fs".into()),
                4 => record.mount_point = "/other".into(),
                5 => record.source.clear(),
                _ => {
                    record.fs_group =
                        protobuf::MessageField::some(protocols::agent::FSGroup::default())
                }
            }
            assert!(resolve(&models, &request, &[record]).is_err());
        }
        for options in [
            &["bind", "rw"][..],
            &["bind", "ro", "rw"],
            &["bind", "ro", "rshared"],
            &["ro"],
        ] {
            assert!(resolve(
                &models,
                &spec("/models/example", "/resolved/raw-input", options),
                &[storage(DRIVER_SCSI_TYPE)]
            )
            .is_err());
        }
    }

    #[test]
    fn shadowing_and_duplicate_mounts_rejected() {
        let models = parse(&config()).unwrap();
        for path in [
            "/models",
            "/models/example/weights",
            "/",
            "/models/example/../other",
        ] {
            assert!(resolve(
                &models,
                &spec(path, "/resolved/raw-input", &["bind", "ro"]),
                &[]
            )
            .is_err());
        }
        let mut request = spec("/models/example", "/resolved/raw-input", &["bind", "ro"]);
        let mount = request.mounts().as_ref().unwrap()[0].clone();
        request.mounts_mut().as_mut().unwrap().push(mount);
        assert!(resolve(&models, &request, &[storage(DRIVER_SCSI_TYPE)]).is_err());
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
    async fn empty_init_and_unrelated_cleanup_preserve_container_state() {
        let mut gate = Gate::new(parse(&config()).unwrap());
        gate.prepare(&mut Spec::default(), &[], "init")
            .await
            .unwrap();
        gate.containers.insert("consumer".into());
        gate.cleanup_container("init").await.unwrap();
        assert!(gate.containers.contains("consumer"));
        assert!(gate
            .validate(&Spec::default(), &[], "next", "sandbox")
            .is_ok());
    }

    #[tokio::test]
    async fn partial_storage_failure_records_only_acquired_references() {
        use std::sync::Arc;
        use tokio::sync::Mutex;
        let logger = slog::Logger::root(slog::Discard, slog::o!());
        for existing_first in [false, true] {
            let sandbox = Arc::new(Mutex::new(crate::sandbox::Sandbox::new(&logger).unwrap()));
            sandbox
                .lock()
                .await
                .add_sandbox_storage("/raw-existing", false)
                .await;
            let existing = Storage {
                driver: "unknown".into(),
                mount_point: "/raw-existing".into(),
                ..Default::default()
            };
            let failing = Storage {
                driver: "unknown".into(),
                mount_point: "/raw-failing".into(),
                ..Default::default()
            };
            let storages = if existing_first {
                vec![existing, failing]
            } else {
                vec![failing, existing]
            };
            assert!(crate::storage::add_storages(
                logger.clone(),
                storages,
                &sandbox,
                Some("failed".into())
            )
            .await
            .is_err());
            let mut s = sandbox.lock().await;
            let acquired = s.container_mounts["failed"].clone();
            assert_eq!(acquired.contains(&"/raw-existing".into()), existing_first);
            for path in acquired {
                s.remove_sandbox_storage(&path).await.unwrap();
            }
            assert_eq!(s.storages["/raw-existing"].ref_count().await, 1);
        }
    }

    #[cfg(feature = "agent-policy")]
    #[tokio::test]
    async fn upstream_policy_example_authorizes_original_block_requests() {
        use base64::{engine::general_purpose::URL_SAFE, Engine};
        use kata_agent_policy::policy::AgentPolicy;
        let example: serde_json::Value =
            serde_json::from_str(include_str!("model-block-policy.example.json")).unwrap();
        let mut policy = AgentPolicy::new();
        let mut rules = include_str!("../../tools/genpolicy/rules.rego").to_string();
        rules.push_str(r#"
policy_data := {"common": {"sfprefix": "unused", "cpath": "unused", "spath": "/run/kata-containers/sandbox/storage"}}
default BlockPolicyCheck := false
BlockPolicyCheck := true if {
    allow_storages([input.expected_storage], [input.storage], "bundle", "sandbox")
    check_mount(input.expected_mount, input.mount, "bundle", "sandbox")
}
"#);
        policy.set_policy(&rules).await.unwrap();
        for (driver, source) in [(DRIVER_SCSI_TYPE, "0:1"), (DRIVER_BLK_PCI_TYPE, "02/03")] {
            let path = format!(
                "/run/kata-containers/sandbox/storage/{}",
                URL_SAFE.encode(source)
            );
            let mut storage = example["storage"].clone();
            storage["driver"] = serde_json::json!(driver);
            storage["source"] = serde_json::json!(source);
            storage["mount_point"] = serde_json::json!(path);
            let mut mount = example["mount"].clone();
            mount["source"] = serde_json::json!(path);
            let request = serde_json::json!({"expected_storage": example["storage"], "expected_mount": example["mount"], "storage": storage, "mount": mount});
            assert!(
                policy
                    .allow_request("BlockPolicyCheck", &request.to_string())
                    .await
                    .unwrap()
                    .0
            );
            for (object, field, value) in [
                (
                    "mount",
                    "source",
                    serde_json::json!("/run/modelwrap/containers/61/mounts/0"),
                ),
                ("mount", "destination", serde_json::json!("/models/other")),
                (
                    "mount",
                    "options",
                    serde_json::json!(["rbind", "rprivate", "rw"]),
                ),
                (
                    "storage",
                    "options",
                    serde_json::json!(["rbind", "rprivate", "rw"]),
                ),
                ("storage", "driver", serde_json::json!("local")),
                ("storage", "source", serde_json::json!("/dev/arbitrary")),
                ("storage", "fstype", serde_json::json!("erofs")),
                (
                    "storage",
                    "mount_point",
                    serde_json::json!("/run/modelwrap/containers/61/mounts/0"),
                ),
            ] {
                let mut changed = request.clone();
                changed[object][field] = value;
                assert!(
                    !policy
                        .allow_request("BlockPolicyCheck", &changed.to_string())
                        .await
                        .unwrap()
                        .0,
                    "{}",
                    changed
                );
            }
        }
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
            let task = tokio::spawn(async move {
                helper_command(&path, "mount", Path::new("/unused"), &[], timeout).await
            });
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
