// SPDX-License-Identifier: Apache-2.0
//! Per-container network policy, enforced inside the guest with cgroup-v2 eBPF programs.
//!
//! Containers share the guest network namespace, so the CNI sees one pod IP for all of them.
//! `rustjail` only applies cgroups when the OCI spec has resources, hence `verify_placement`.

// Some items are used only by the tests.
#![allow(dead_code)]

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

pub const DNS_STUB_PORT: u16 = 53;
/// The filtered resolver for `egress-allowlist` containers.
pub const DNS_STUB_ADDR: &str = "127.0.0.53";
/// Guest-owned resolver file bind-mounted over a filtered container's `/etc/resolv.conf`.
pub const RESOLV_CONF: &str = "/run/podvm/resolv-attestation.conf";
pub const RESERVED_PORTS_SYSCTL: &str = "net.ipv4.ip_local_reserved_ports";
/// Sysctls that close bypasses the eBPF programs cannot cover.
pub const HARDENING_SYSCTLS: [(&str, &str); 3] = [
    // io_uring can submit socket work on paths that skip cgroup hooks.
    ("kernel.io_uring_disabled", "2"),
    // A user namespace lets a container create a network namespace of its own.
    ("user.max_user_namespaces", "0"),
    // SYN-cookie SYN-ACKs bypass every cgroup program, so an undeclared listener could complete
    // handshakes under a SYN flood; without cookies a full queue drops SYNs instead.
    ("net.ipv4.tcp_syncookies", "0"),
];

/// Write a sysctl through `/proc/sys` and read it back, since the kernel normalises some values.
/// Every failure is returned: a partly applied hardening set is a silent downgrade.
pub fn write_sysctl(name: &str, value: &str) -> Result<()> {
    let path = PathBuf::from("/proc/sys").join(name.replace('.', "/"));
    std::fs::write(&path, value).with_context(|| format!("writing sysctl {name}={value}"))?;
    let readback =
        std::fs::read_to_string(&path).with_context(|| format!("reading back sysctl {name}"))?;
    let readback = readback.trim();
    // ip_local_reserved_ports echoes a normalised, possibly reordered list; compare as sets.
    if name == RESERVED_PORTS_SYSCTL {
        if ports_from_sysctl(readback) != ports_from_sysctl(value) {
            bail!("sysctl {name} read back as {readback:?}, wanted {value:?}");
        }
    } else if readback != value {
        bail!("sysctl {name} read back as {readback:?}, wanted {value:?}");
    }
    Ok(())
}

pub fn ports_from_sysctl(value: &str) -> BTreeSet<u16> {
    // The kernel echoes ranges ("9000-9002") as written, so they must parse too.
    let mut ports = BTreeSet::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (start, end) = match entry.split_once('-') {
            Some((start, end)) => (start.trim(), end.trim()),
            None => (entry, entry),
        };
        if let (Ok(start), Ok(end)) = (start.parse::<u16>(), end.parse::<u16>()) {
            if start <= end {
                ports.extend(start..=end);
            }
        }
    }
    ports
}

/// `ports` as ascending ranges, consecutive ports merged.
pub fn port_ranges(ports: impl IntoIterator<Item = u16>) -> Vec<PortRange> {
    let ports: BTreeSet<u16> = ports.into_iter().collect();
    let mut ranges: Vec<PortRange> = Vec::new();
    for port in ports {
        match ranges.last_mut() {
            Some(last) if u32::from(last.end) + 1 == u32::from(port) => last.end = port,
            _ => ranges.push(PortRange::single(port)),
        }
    }
    ranges
}

pub fn apply_sysctls<F>(policy: &Policy, mut write: F) -> Result<()>
where
    F: FnMut(&str, &str) -> Result<()>,
{
    for (name, value) in HARDENING_SYSCTLS {
        write(name, value)?;
    }
    let reserved = policy.reserved_ports_value();
    if !reserved.is_empty() {
        write(RESERVED_PORTS_SYSCTL, &reserved)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// No traffic may leave the loopback interface. Inbound connections are unaffected.
    LoopbackOnly,
    /// Outbound traffic only on `port_allow`, to `cidr_allow` or the `dns_allow` addresses.
    EgressAllowlist,
}

/// A bare port means TCP; `udp` must be explicit.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    pub const fn number(self) -> u8 {
        match self {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
        }
    }
}

/// An inclusive port range; a bare port in the JSON is a range of one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub const fn single(port: u16) -> Self {
        Self { start: port, end: port }
    }

    pub const fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct PortRule {
    pub range: PortRange,
    pub protocol: Protocol,
}

impl PortRule {
    pub const fn tcp(range: PortRange) -> Self {
        Self { range, protocol: Protocol::Tcp }
    }
}

impl Serialize for PortRange {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.start == self.end {
            serializer.serialize_u16(self.start)
        } else {
            serializer.serialize_str(&format!("{}-{}", self.start, self.end))
        }
    }
}

impl Serialize for PortRule {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ports = if self.range.start == self.range.end {
            self.range.start.to_string()
        } else {
            format!("{}-{}", self.range.start, self.range.end)
        };
        serializer.serialize_str(&match self.protocol {
            Protocol::Tcp => ports,
            Protocol::Udp => format!("{ports}/udp"),
        })
    }
}

impl<'de> Deserialize<'de> for PortRule {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = PortRule;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a port, a \"start-end\" range, or either with a /tcp or /udp suffix")
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<PortRule, E> {
                Ok(PortRule::tcp(PortRange::deserialize(
                    serde::de::value::U64Deserializer::<E>::new(value),
                )?))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<PortRule, E> {
                let (ports, protocol) = match value.rsplit_once('/') {
                    Some((ports, "tcp")) => (ports, Protocol::Tcp),
                    Some((ports, "udp")) => (ports, Protocol::Udp),
                    Some((_, other)) => {
                        return Err(E::custom(format!(
                            "{value:?}: unknown protocol {other:?}, expected tcp or udp"
                        )))
                    }
                    None => (value, Protocol::Tcp),
                };
                Ok(PortRule {
                    range: PortRange::deserialize(serde::de::value::StrDeserializer::<E>::new(
                        ports,
                    ))?,
                    protocol,
                })
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = PortRange;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a port number or an inclusive \"start-end\" range")
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<PortRange, E> {
                let port = u16::try_from(value)
                    .map_err(|_| E::custom(format!("port {value} is out of range")))?;
                Ok(PortRange::single(port))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<PortRange, E> {
                let (start, end) = match value.split_once('-') {
                    Some((start, end)) => (start, end),
                    None => (value, value),
                };
                let start = parse_port(start)
                    .map_err(|e| E::custom(format!("{value:?}: {e}")))?;
                let end = parse_port(end).map_err(|e| E::custom(format!("{value:?}: {e}")))?;
                if start > end {
                    return Err(E::custom(format!(
                        "{value:?}: range start {start} is above its end {end}"
                    )));
                }
                Ok(PortRange { start, end })
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

fn parse_port(text: &str) -> Result<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("{text:?} is not a port number");
    }
    text.parse::<u16>()
        .map_err(|_| anyhow!("{text:?} is out of range"))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerPolicy {
    pub mode: Mode,
    /// Ports the container serves on, reserved against siblings: `8000`, `8000-8010`, `53/udp`.
    /// The protocol governs binding only; a container reaches its own loopback ports over either.
    #[serde(default)]
    pub service_ports: Vec<PortRule>,
    /// Names the in-guest DNS filter resolves; everything else gets REFUSED.
    #[serde(default)]
    pub dns_allow: Vec<String>,
    /// Outbound ports in `egress-allowlist` mode; a bare port means TCP.
    #[serde(default)]
    pub port_allow: Vec<PortRule>,
    /// Destination prefixes; when this and `dns_allow` are both empty, any destination passes.
    #[serde(default)]
    pub cidr_allow: Vec<String>,
}

impl ContainerPolicy {
    /// Whether destinations are constrained. True with `dns_allow` alone, whose addresses only the
    /// DNS filter knows, so the eBPF must not fall back to "any address".
    pub fn destination_axis(&self) -> bool {
        !self.cidr_allow.is_empty() || !self.dns_allow.is_empty()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(deserialize_with = "deserialize_containers")]
    pub containers: BTreeMap<String, ContainerPolicy>,
}

/// Reject duplicate keys; serde_json would keep the last one.
fn deserialize_containers<'de, D>(
    deserializer: D,
) -> std::result::Result<BTreeMap<String, ContainerPolicy>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ContainersVisitor;
    impl<'de> serde::de::Visitor<'de> for ContainersVisitor {
        type Value = BTreeMap<String, ContainerPolicy>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map of unique container names to network policies")
        }

        fn visit_map<M>(self, mut map: M) -> std::result::Result<Self::Value, M::Error>
        where
            M: serde::de::MapAccess<'de>,
        {
            let mut containers = BTreeMap::new();
            while let Some(name) = map.next_key::<String>()? {
                if containers.contains_key(&name) {
                    return Err(serde::de::Error::custom(format!(
                        "duplicate container name {name:?}"
                    )));
                }
                containers.insert(name, map.next_value()?);
            }
            Ok(containers)
        }
    }
    deserializer.deserialize_map(ContainersVisitor)
}

impl Policy {
    pub fn deny_all() -> Self {
        Policy {
            version: 1,
            containers: BTreeMap::new(),
        }
    }

    pub fn container(&self, name: &str) -> Result<&ContainerPolicy> {
        self.containers
            .get(name)
            .ok_or_else(|| anyhow!("container {name} has no network policy"))
    }

    /// Ports kept out of the ephemeral range. The sysctl has no protocol dimension, so `8000/tcp`
    /// reserves UDP 8000 too.
    pub fn reserved_ports(&self) -> BTreeSet<u16> {
        let mut ports = BTreeSet::from([DNS_STUB_PORT]);
        for policy in self.containers.values() {
            for rule in &policy.service_ports {
                ports.extend(rule.range.start..=rule.range.end);
            }
        }
        ports
    }

    /// `reserved_ports` in `ip_local_reserved_ports` syntax.
    pub fn reserved_ports_value(&self) -> String {
        port_ranges(self.reserved_ports())
            .iter()
            .map(|range| {
                if range.start == range.end {
                    range.start.to_string()
                } else {
                    format!("{}-{}", range.start, range.end)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn dns_allow(&self) -> BTreeSet<String> {
        self.containers
            .values()
            .flat_map(|policy| {
                policy
                    .dns_allow
                    .iter()
                    .map(|name| normalized_dns_name(name))
            })
            .collect()
    }

    fn filtered(&self) -> impl Iterator<Item = (&String, &ContainerPolicy)> {
        self.containers
            .iter()
            .filter(|(_, policy)| policy.mode == Mode::EgressAllowlist)
    }
}

fn normalized_dns_name(name: &str) -> String {
    name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase()
}

pub fn parse(raw: &str) -> Result<Policy> {
    let policy: Policy = serde_json::from_str(raw).context("network-policy.json is not valid")?;
    validate(&policy)?;
    Ok(policy)
}

pub fn validate(policy: &Policy) -> Result<()> {
    if policy.version != 1 {
        bail!(
            "network-policy.json version {} is not supported",
            policy.version
        );
    }
    let filtered = policy.filtered().count();
    if filtered > 1 {
        // The DNS filter is shared, so a second allowlist would silently widen the first.
        bail!("at most one container may use egress-allowlist, found {filtered}");
    }
    for (name, entry) in &policy.containers {
        if !valid_container_name(name) {
            bail!("network-policy.json container name {name:?} is not a DNS label");
        }
        if entry.service_ports.len() > 64 || entry.port_allow.len() > 64 {
            bail!("container {name}: too many port rules");
        }
        // Capped: an accidental `0-65535` would reserve every port.
        let served: u32 = entry
            .service_ports
            .iter()
            .map(|rule| u32::from(rule.range.end - rule.range.start) + 1)
            .sum();
        if served > MAX_SERVICE_PORTS {
            bail!(
                "container {name}: service_ports covers {served} ports, more than the {MAX_SERVICE_PORTS} allowed"
            );
        }
        if entry.dns_allow.len() > 256 || entry.cidr_allow.len() > MAX_CIDR_ALLOW {
            bail!("container {name}: too many DNS or CIDR rules");
        }
        for rule in &entry.service_ports {
            if rule.range.start == 0 || rule.range.contains(DNS_STUB_PORT) {
                bail!(
                    "container {name}: service_ports may not contain port 0 or {}",
                    DNS_STUB_PORT
                );
            }
        }
        let mut names = BTreeSet::new();
        for dns_name in &entry.dns_allow {
            if !valid_dns_name(dns_name) {
                bail!("container {name}: dns_allow entry {dns_name:?} is not a DNS name");
            }
            if !names.insert(normalized_dns_name(dns_name)) {
                bail!("container {name}: duplicate effective DNS name {dns_name:?}");
            }
        }
        let mut listener_ports: Vec<(u16, u16, Protocol)> = Vec::new();
        for rule in &entry.service_ports {
            if listener_ports.iter().any(|(start, end, protocol)| {
                *protocol == rule.protocol && rule.range.start <= *end && *start <= rule.range.end
            }) {
                bail!(
                    "container {name}: service port range {}-{} overlaps another",
                    rule.range.start,
                    rule.range.end
                );
            }
            listener_ports.push((rule.range.start, rule.range.end, rule.protocol));
        }
        let mut outbound = BTreeSet::new();
        for rule in &entry.port_allow {
            if rule.range.start == 0 {
                bail!("container {name}: port_allow may not contain port 0");
            }
            let clashes = outbound.iter().any(|other: &PortRule| {
                other.protocol == rule.protocol
                    && rule.range.start <= other.range.end
                    && other.range.start <= rule.range.end
            });
            if clashes {
                bail!(
                    "container {name}: port_allow range {}-{} overlaps another",
                    rule.range.start,
                    rule.range.end
                );
            }
            outbound.insert(*rule);
        }
        for prefix in &entry.cidr_allow {
            parse_cidr(prefix)
                .with_context(|| format!("container {name}: cidr_allow entry {prefix:?}"))?;
        }
        if entry.mode == Mode::EgressAllowlist {
            if entry.port_allow.is_empty() {
                // An allowlist with no ports allows nothing: more likely a mistake than intent.
                bail!("container {name}: egress-allowlist needs at least one port_allow entry");
            }
        } else if !entry.dns_allow.is_empty()
            || !entry.port_allow.is_empty()
            || !entry.cidr_allow.is_empty()
        {
            // These fields would be silently ignored in `loopback-only`.
            bail!("container {name}: loopback-only takes no egress or resolver fields");
        }
    }
    // A service port belongs to one container, whatever the protocol: on loopback a container
    // reaches its own service ports over either, so a sibling's 8000/udp would reach 8000/tcp.
    let mut served: Vec<(&String, PortRule)> = Vec::new();
    for (name, entry) in &policy.containers {
        for rule in &entry.service_ports {
            if let Some((other, _)) = served.iter().find(|(other, taken)| {
                *other != name && rule.range.start <= taken.range.end && taken.range.start <= rule.range.end
            }) {
                bail!(
                    "service port {}-{} is declared by both {other} and {name}",
                    rule.range.start,
                    rule.range.end
                );
            }
        }
        served.extend(entry.service_ports.iter().map(|rule| (name, *rule)));
    }
    Ok(())
}

/// The annotation genpolicy pins on every container it lets the sandbox create.
const CONTAINER_NAME_ANNOTATION: &str = "io.kubernetes.cri.container-name";

/// Container names a genpolicy Rego document allows, read from its `policy_data`. `None` when
/// there is no `policy_data` (a hand-written policy).
pub fn rego_container_names(rego: &str) -> Result<Option<BTreeSet<String>>> {
    const MARKER: &str = "\npolicy_data :=";
    let Some(start) = rego.find(MARKER) else {
        return Ok(None);
    };
    let json = rego[start + MARKER.len()..].trim_start();
    let data = serde_json::Deserializer::from_str(json)
        .into_iter::<serde_json::Value>()
        .next()
        .context("policy_data has no value")?
        .context("policy_data is not JSON")?;
    let containers = data
        .get("containers")
        .and_then(|containers| containers.as_array())
        .context("policy_data has no containers list")?;
    Ok(Some(
        containers
            .iter()
            .filter_map(|container| find_string(container, CONTAINER_NAME_ANNOTATION))
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect(),
    ))
}

fn find_string<'a>(value: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    match value {
        serde_json::Value::Object(map) => map
            .get(key)
            .and_then(|found| found.as_str())
            .or_else(|| map.values().find_map(|child| find_string(child, key))),
        serde_json::Value::Array(items) => items.iter().find_map(|child| find_string(child, key)),
        _ => None,
    }
}

/// Every container the policy names must be one the genpolicy agent policy creates. Without
/// that pinned list the host picks names freely and can run a container under an unlisted one.
pub fn check_targets(policy: &Policy, rego: Option<&str>) -> Result<()> {
    if policy.containers.is_empty() {
        return Ok(());
    }
    let rego = rego.context("network-policy.json needs the agent policy (policy.rego) in the same Init-Data")?;
    let names = rego_container_names(rego)?
        .context("network-policy.json needs a genpolicy agent policy, but policy.rego has no policy_data")?;
    let unknown: Vec<&String> = policy
        .containers
        .keys()
        .filter(|name| !names.contains(*name))
        .collect();
    if !unknown.is_empty() {
        bail!("network-policy.json names {unknown:?}, but the agent policy only creates {names:?}");
    }
    Ok(())
}

/// Validate and apply `network-policy.json` at boot. On error the caller refuses CreateSandbox
/// and CreateContainer (see `refusal`) instead of exiting, which the host sees only as a timeout.
pub fn prepare<F>(parsed: std::result::Result<Policy, String>, rego: Option<&str>, write: F) -> Result<Policy>
where
    F: FnMut(&str, &str) -> Result<()>,
{
    let policy = parsed.map_err(|reason| anyhow!(reason))?;
    validate(&policy)?;
    check_targets(&policy, rego)?;
    if !policy.containers.is_empty() {
        apply_sysctls(&policy, write)?;
    }
    Ok(policy)
}

pub fn refusal(reason: &str) -> String {
    format!("network-policy.json refused: {reason}")
}

fn valid_container_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && name.as_bytes()[0] != b'-'
        && name.as_bytes()[name.len() - 1] != b'-'
}

fn valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && label.as_bytes()[0] != b'-'
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    pub addr: [u8; 16],
    pub bits: u8,
    pub v6: bool,
}

impl Cidr {
    pub fn network(&self) -> [u8; 16] {
        let width = if self.v6 { 16 } else { 4 };
        let mut network = [0u8; 16];
        for (index, byte) in self.addr[..width].iter().enumerate() {
            let remaining = i32::from(self.bits) - (index as i32) * 8;
            network[index] = match remaining {
                r if r >= 8 => *byte,
                r if r <= 0 => 0,
                r => byte & (0xffu8 << (8 - r)),
            };
        }
        network
    }

    pub fn contains(&self, addr: [u8; 16]) -> bool {
        if self.v6 {
            prefix_matches(&self.addr, &addr, self.bits)
        } else {
            prefix_matches(&self.addr[..4], &addr[..4], self.bits)
        }
    }
}

fn prefix_matches(prefix: &[u8], addr: &[u8], bits: u8) -> bool {
    let whole = usize::from(bits / 8);
    let rest = bits % 8;
    if prefix[..whole] != addr[..whole] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    prefix[whole] & mask == addr[whole] & mask
}

pub fn parse_cidr(prefix: &str) -> Result<Cidr> {
    let (addr, bits) = prefix
        .split_once('/')
        .ok_or_else(|| anyhow!("missing prefix length"))?;
    // Digits only: `u8::from_str` would also take `+8`.
    if bits.is_empty() || bits.len() > 3 || !bits.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid prefix length {bits:?}");
    }
    let bits: u8 = bits.parse().context("invalid prefix length")?;
    let mut out = [0u8; 16];
    let cidr = if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        if bits > 32 {
            bail!("prefix length {bits} exceeds 32 for an IPv4 address");
        }
        out[..4].copy_from_slice(&v4.octets());
        Cidr { addr: out, bits, v6: false }
    } else {
        let v6 = addr
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| anyhow!("not an IP address"))?;
        if bits > 128 {
            bail!("prefix length {bits} exceeds 128 for an IPv6 address");
        }
        out.copy_from_slice(&v6.octets());
        Cidr { addr: out, bits, v6: true }
    };
    // `10.0.0.5/8` reads like one host but admits all of 10/8, so only the network form is taken.
    let network = cidr.network();
    if network != cidr.addr {
        let shown = if cidr.v6 {
            std::net::Ipv6Addr::from(network).to_string()
        } else {
            std::net::Ipv4Addr::new(network[0], network[1], network[2], network[3]).to_string()
        };
        bail!("{prefix} has host bits set; write the network as {shown}/{bits}");
    }
    // The programs judge `::ffff:a.b.c.d` by IPv4 prefixes, so a mapped prefix matches nothing.
    if cidr.v6 && cidr.bits >= 96 {
        if let Some(v4) = std::net::Ipv6Addr::from(cidr.addr).to_ipv4_mapped() {
            bail!("{prefix} is IPv4-mapped; write it as {v4}/{}", cidr.bits - 96);
        }
    }
    Ok(cidr)
}

/// Whether `addr` is in `cidrs`. Without a destination axis every address passes; with one and
/// no `cidrs` (a `dns_allow`-only policy) none does.
pub fn address_allowed(cidrs: &[Cidr], constrained: bool, addr: [u8; 16], v6: bool) -> bool {
    if !constrained {
        return true;
    }
    cidrs
        .iter()
        .any(|cidr| cidr.v6 == v6 && cidr.contains(addr))
}

#[derive(Debug)]
pub struct PlacementError(pub String);

impl fmt::Display for PlacementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PlacementError {}

/// Read placement from procfs rather than rebuilding rustjail's manager-specific path formats.
pub fn resolve_cgroup_dir(manager_dir: &Path, proc_cgroup: &str) -> Result<(PathBuf, String)> {
    let actual = normalize(&cgroup_membership(proc_cgroup)?);
    if actual == "/" {
        return Err(PlacementError("container process is still in the root cgroup".into()).into());
    }
    if Path::new(&actual)
        .components()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(PlacementError(format!("invalid cgroup path {actual:?}")).into());
    }
    let manager_relative = manager_dir
        .strip_prefix("/sys/fs/cgroup")
        .with_context(|| {
            format!(
                "cgroup manager path {} is outside /sys/fs/cgroup",
                manager_dir.display()
            )
        })?;
    let expected = normalize(&manager_relative.to_string_lossy());
    if expected != "/" && !Path::new(&actual).starts_with(Path::new(&expected)) {
        return Err(PlacementError(format!(
            "container process is in cgroup {actual}, outside manager path {expected}"
        ))
        .into());
    }
    Ok((
        Path::new("/sys/fs/cgroup").join(actual.trim_start_matches('/')),
        actual,
    ))
}

/// The path in the `0::<path>` line of `/proc/<pid>/cgroup` (cgroup v2).
pub fn cgroup_membership(proc_cgroup: &str) -> Result<String> {
    let mut found = None;
    for line in proc_cgroup.lines().filter(|line| !line.trim().is_empty()) {
        let (hierarchy, rest) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("/proc/<pid>/cgroup line {line:?} has no hierarchy"))?;
        if hierarchy != "0" {
            continue;
        }
        let (_, path) = rest
            .split_once(':')
            .ok_or_else(|| anyhow!("/proc/<pid>/cgroup line {line:?} has no controllers field"))?;
        if found.is_some() {
            bail!("/proc/<pid>/cgroup reports more than one cgroup v2 line");
        }
        found = Some(path.to_string());
    }
    found.ok_or_else(|| anyhow!("/proc/<pid>/cgroup reports no cgroup v2 line"))
}

/// cgroupfs reports the root as `/`; a path stripped of `/sys/fs/cgroup` loses its leading slash.
fn normalize(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

/// Check the process is in the cgroup the programs attach to; otherwise every attach succeeds and
/// nothing is enforced.
pub fn verify_placement(
    expected: &str,
    proc_cgroup: &str,
    cgroup_procs: &str,
    pid: i32,
) -> Result<()> {
    let expected = normalize(expected);
    let actual = normalize(&cgroup_membership(proc_cgroup)?);
    if actual == "/" || actual != expected {
        return Err(PlacementError(format!(
            "container process {pid} is in cgroup {actual}, expected {expected}; \
             network policy would not apply"
        ))
        .into());
    }
    let listed = cgroup_procs
        .lines()
        .filter_map(|line| line.trim().parse::<i32>().ok())
        .any(|listed| listed == pid);
    if !listed {
        return Err(PlacementError(format!(
            "{expected}/cgroup.procs does not list container process {pid}"
        ))
        .into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// eBPF enforcement
// Each container gets its own copy of every program and its own frozen policy map.
// ---------------------------------------------------------------------------------------------

/// `net-policy.bpf.c`, compiled by the agent build.
static OBJECT: &[u8] = include_bytes!("net_policy.bpf.o");

/// From `enum bpf_prog_type` and `enum bpf_attach_type` in the Linux UAPI.
pub const BPF_PROG_TYPE_CGROUP_SOCK: u32 = 9;
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;
pub const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;
pub const BPF_CGROUP_INET4_BIND: u32 = 8;
pub const BPF_CGROUP_INET6_BIND: u32 = 9;
pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;
pub const BPF_CGROUP_UDP4_SENDMSG: u32 = 14;
pub const BPF_CGROUP_UDP6_SENDMSG: u32 = 15;
pub const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
/// Runs on every packet the cgroup sends, after routing.
pub const BPF_CGROUP_INET_EGRESS: u32 = 1;

pub const ALLOW: i64 = 1;
pub const DENY: i64 = 0;

/// Total ports one container's `service_ports` may cover.
pub const MAX_SERVICE_PORTS: u32 = 1024;

/// The kernel's `struct bpf_insn`; `regs` packs `dst_reg` (low nibble) and `src_reg`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Insn {
    pub code: u8,
    pub regs: u8,
    pub off: i16,
    pub imm: i32,
}

const _: [(); 8] = [(); std::mem::size_of::<Insn>()];
const _: [(); 2] = [(); std::mem::offset_of!(Insn, off)];
const _: [(); 4] = [(); std::mem::offset_of!(Insn, imm)];

impl Insn {
    pub const fn dst(&self) -> u8 {
        self.regs & 0x0f
    }

    pub const fn src(&self) -> u8 {
        self.regs >> 4
    }
}

/// `BPF_LD | BPF_IMM | BPF_DW`: a 64-bit immediate, or a map reference, in two instruction slots.
const OP_LD_IMM64: u8 = 0x18;
/// `BPF_JMP | BPF_CALL`.
const OP_CALL: u8 = 0x85;
/// `src_reg` marker for `LD_IMM64`: the immediate indexes `fd_array`, not a raw fd, so one
/// relocated program can be loaded for every container.
const BPF_PSEUDO_MAP_IDX: u8 = 5;
/// `src_reg` marker for `LD_IMM64`: the address of the value of the single-element map at
/// `fd_array[imm]`, plus the offset in the second slot's immediate.
const BPF_PSEUDO_MAP_IDX_VALUE: u8 = 6;
const RESOLVED_MAP_INDEX: i32 = 0;
const POLICY_MAP_INDEX: i32 = 1;

/// From `enum bpf_func_id` in the Linux UAPI.
const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_FUNC_KTIME_GET_NS: i32 = 5;

const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// LRU, so a long-lived container cannot grow the resolved map without bound.
const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
/// With the map also frozen, the verifier treats its contents as constants.
const BPF_F_RDONLY_PROG: u32 = 1 << 7;
const RESOLVED_MAP_ENTRIES: u32 = 1024;
/// IPv6, or IPv4 as `::ffff:a.b.c.d`.
pub const RESOLVED_KEY_LEN: u32 = 16;
/// Expiry, in nanoseconds on CLOCK_MONOTONIC.
const RESOLVED_VALUE_LEN: u32 = 8;
/// Floor on how long a published address stays reachable, in seconds: runtimes keep answers
/// past their TTL (Java for 30 s), and an expired address would look like a broken network.
pub const RESOLVED_MIN_TTL: u32 = 300;
/// Cap on how long a published address and a cached answer last, in seconds.
pub const RESOLVED_MAX_TTL: u32 = 3600;

/// Offsets in `struct policy` of `net-policy.bpf.c`. Kept in sync by the reader's `LEN` check and
/// by the tests, which run the compiled programs on policies encoded here.
mod layout {
    /// One bit per port, indexed by the port number.
    pub const PORT_SET: usize = 8192;
    pub const MODE: usize = 0;
    pub const CONSTRAINED: usize = 4;
    pub const ANY_V4: usize = 8;
    pub const ANY_V6: usize = 12;
    pub const CIDR4_COUNT: usize = 16;
    pub const CIDR6_COUNT: usize = 20;
    pub const OWN_TCP: usize = 24;
    pub const OWN_UDP: usize = OWN_TCP + PORT_SET;
    pub const RESERVED: usize = OWN_UDP + PORT_SET;
    pub const ALLOW_TCP: usize = RESERVED + PORT_SET;
    pub const ALLOW_UDP: usize = ALLOW_TCP + PORT_SET;
    pub const CIDR4: usize = ALLOW_UDP + PORT_SET;
    /// A mask word and a network word.
    pub const CIDR4_ENTRY: usize = 8;
    pub const CIDR6: usize = CIDR4 + super::MAX_CIDR4 * CIDR4_ENTRY;
    /// Four mask words, then four network words.
    pub const CIDR6_ENTRY: usize = 32;
    pub const LEN: usize = CIDR6 + super::MAX_CIDR6 * CIDR6_ENTRY;
}

const MODE_LOOPBACK_ONLY: u32 = 1;
const MODE_EGRESS_ALLOWLIST: u32 = 2;
/// Prefixes per `cidr_allow`. Either family may fill it, so each gets room for all of them.
pub const MAX_CIDR_ALLOW: usize = 256;
pub const MAX_CIDR4: usize = MAX_CIDR_ALLOW;
pub const MAX_CIDR6: usize = MAX_CIDR_ALLOW;

#[derive(Clone, Debug)]
pub struct ProgramPolicy {
    pub mode: Mode,
    pub service_ports: Vec<PortRule>,
    /// Every container's service ports and the DNS stub port.
    pub reserved: Vec<u16>,
    pub port_allow: Vec<PortRule>,
    pub cidrs: Vec<Cidr>,
    /// See `ContainerPolicy::destination_axis`.
    pub constrained: bool,
}

impl ProgramPolicy {
    pub fn new(policy: &ContainerPolicy, reserved_ports: &BTreeSet<u16>) -> Result<Self> {
        let egress = policy.mode == Mode::EgressAllowlist;
        let cidrs = if egress {
            policy
                .cidr_allow
                .iter()
                .map(|prefix| parse_cidr(prefix))
                .collect::<Result<_>>()?
        } else {
            Vec::new()
        };
        Ok(ProgramPolicy {
            mode: policy.mode,
            service_ports: policy.service_ports.clone(),
            reserved: reserved_ports.iter().copied().collect(),
            port_allow: if egress { policy.port_allow.clone() } else { Vec::new() },
            cidrs,
            constrained: egress && policy.destination_axis(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let egress = self.mode == Mode::EgressAllowlist;
        if egress && self.port_allow.is_empty() {
            bail!("egress-allowlist needs at least one port rule");
        }
        let mut out = vec![0u8; layout::LEN];
        let mode = if egress { MODE_EGRESS_ALLOWLIST } else { MODE_LOOPBACK_ONLY };
        put_u32(&mut out, layout::MODE, mode);
        put_u32(&mut out, layout::CONSTRAINED, u32::from(self.constrained));

        for (rules, tcp, udp) in [
            (&self.service_ports, layout::OWN_TCP, layout::OWN_UDP),
            (&self.port_allow, layout::ALLOW_TCP, layout::ALLOW_UDP),
        ] {
            for rule in rules {
                let set = match rule.protocol {
                    Protocol::Tcp => tcp,
                    Protocol::Udp => udp,
                };
                for port in rule.range.start..=rule.range.end {
                    set_port(&mut out, set, port);
                }
            }
        }
        for port in &self.reserved {
            set_port(&mut out, layout::RESERVED, *port);
        }

        // A /0 prefix admits every address of its family, so the programs skip the list.
        let any = |v6: bool| self.cidrs.iter().any(|cidr| cidr.v6 == v6 && cidr.bits == 0);
        put_u32(&mut out, layout::ANY_V4, u32::from(any(false)));
        put_u32(&mut out, layout::ANY_V6, u32::from(any(true)));
        let v4: Vec<&Cidr> = self.cidrs.iter().filter(|cidr| !cidr.v6).collect();
        let v6: Vec<&Cidr> = self.cidrs.iter().filter(|cidr| cidr.v6).collect();
        if v4.len() > MAX_CIDR4 || v6.len() > MAX_CIDR6 {
            bail!(
                "cidr_allow holds {} IPv4 and {} IPv6 prefixes; at most {MAX_CIDR4} and {MAX_CIDR6} are supported",
                v4.len(),
                v6.len()
            );
        }
        put_u32(&mut out, layout::CIDR4_COUNT, v4.len() as u32);
        put_u32(&mut out, layout::CIDR6_COUNT, v6.len() as u32);
        for (index, cidr) in v4.iter().enumerate() {
            let at = layout::CIDR4 + index * layout::CIDR4_ENTRY;
            let (mask, network) = masked_word(cidr, 0);
            out[at..at + 4].copy_from_slice(&mask);
            out[at + 4..at + 8].copy_from_slice(&network);
        }
        for (index, cidr) in v6.iter().enumerate() {
            let at = layout::CIDR6 + index * layout::CIDR6_ENTRY;
            for word in 0..4 {
                let (mask, network) = masked_word(cidr, word);
                out[at + word * 4..at + word * 4 + 4].copy_from_slice(&mask);
                out[at + 16 + word * 4..at + 16 + word * 4 + 4].copy_from_slice(&network);
            }
        }
        Ok(out)
    }
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn set_port(out: &mut [u8], set: usize, port: u16) {
    out[set + usize::from(port >> 3)] |= 1 << (port & 7);
}

/// The mask and the network of `cidr` over its `word`th four bytes, in address order.
fn masked_word(cidr: &Cidr, word: usize) -> ([u8; 4], [u8; 4]) {
    let mut mask = [0u8; 4];
    let mut network = [0u8; 4];
    for byte in 0..4 {
        let index = word * 4 + byte;
        let remaining = i16::from(cidr.bits) - (index * 8) as i16;
        let byte_mask = if remaining >= 8 {
            0xff
        } else if remaining <= 0 {
            0
        } else {
            0xffu8 << (8 - remaining as u8)
        };
        mask[byte] = byte_mask;
        network[byte] = cidr.addr[index] & byte_mask;
    }
    (mask, network)
}

#[derive(Debug)]
pub struct Programs {
    /// `cgroup/sock_create`: which sockets may exist.
    pub sock_create: Vec<Insn>,
    /// `cgroup/connect4` and `cgroup/sendmsg4`.
    pub outbound4: Vec<Insn>,
    /// `cgroup/connect6` and `cgroup/sendmsg6`.
    pub outbound6: Vec<Insn>,
    pub bind4: Vec<Insn>,
    pub bind6: Vec<Insn>,
    /// `cgroup_skb/egress`: the packet-level backstop.
    pub egress: Vec<Insn>,
    pub license: std::ffi::CString,
}

pub fn programs() -> Result<&'static Programs> {
    static PROGRAMS: std::sync::OnceLock<std::result::Result<Programs, String>> = std::sync::OnceLock::new();
    PROGRAMS
        .get_or_init(|| read_object(OBJECT).map_err(|e| format!("{e:#}")))
        .as_ref()
        .map_err(|e| anyhow!("reading the embedded network-policy programs: {e}"))
}

const ELF_HEADER_LEN: usize = 64;
const ELF_SECTION_LEN: usize = 64;
const ELF_SYMBOL_LEN: usize = 24;
const ELF_REL_LEN: usize = 16;
const ET_REL: u16 = 1;
const EM_BPF: u16 = 247;
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_REL: u32 = 9;
/// LLVM's address-significance table: linker metadata, not loaded.
const SHT_LLVM_ADDRSIG: u32 = 0x6fff_4c03;
/// `R_BPF_64_64`: the address of a symbol, for the `LD_IMM64` at the relocated offset.
const R_BPF_64_64: u32 = 1;
const PROGRAM_SECTION: &str = "netpol/";

struct Section<'a> {
    name: &'a str,
    kind: u32,
    data: &'a [u8],
    link: usize,
    info: usize,
}

/// `at` may come from the object itself, so the bounds arithmetic must not overflow.
fn field(bytes: &[u8], at: usize, len: usize) -> Result<&[u8]> {
    bytes
        .get(at..)
        .and_then(|rest| rest.get(..len))
        .context("truncated object")
}

fn le_u16(bytes: &[u8], at: usize) -> Result<u16> {
    let field = field(bytes, at, 2)?;
    Ok(u16::from_le_bytes([field[0], field[1]]))
}

fn le_u32(bytes: &[u8], at: usize) -> Result<u32> {
    let field = field(bytes, at, 4)?;
    Ok(u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
}

fn le_u64(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from(le_u32(bytes, at)?) | (u64::from(le_u32(bytes, at + 4)?) << 32))
}

fn le_usize(bytes: &[u8], at: usize) -> Result<usize> {
    usize::try_from(le_u64(bytes, at)?).context("object offset out of range")
}

fn elf_string(table: &[u8], at: usize) -> Result<&str> {
    let rest = table.get(at..).context("string outside its table")?;
    let end = rest.iter().position(|byte| *byte == 0).context("unterminated string")?;
    std::str::from_utf8(&rest[..end]).context("section or symbol name is not UTF-8")
}

/// Read the compiled object, resolving map references. Not a general ELF loader: anything
/// `net-policy.bpf.c` does not compile to is refused rather than guessed at.
fn read_object(bytes: &[u8]) -> Result<Programs> {
    if bytes.len() < ELF_HEADER_LEN || &bytes[..4] != b"\x7fELF" {
        bail!("not an ELF object");
    }
    // EI_CLASS = ELFCLASS64, EI_DATA = ELFDATA2LSB.
    if bytes[4] != 2 || bytes[5] != 1 {
        bail!("not a 64-bit little-endian object");
    }
    if le_u16(bytes, 16)? != ET_REL || le_u16(bytes, 18)? != EM_BPF {
        bail!("not a relocatable eBPF object");
    }
    let section_table = le_usize(bytes, 40)?;
    if usize::from(le_u16(bytes, 58)?) != ELF_SECTION_LEN {
        bail!("unexpected section header size");
    }
    let section_count = usize::from(le_u16(bytes, 60)?);
    let names_index = usize::from(le_u16(bytes, 62)?);

    let header = |index: usize| -> Result<&[u8]> {
        let at = section_table
            .checked_add(index * ELF_SECTION_LEN)
            .context("truncated section table")?;
        field(bytes, at, ELF_SECTION_LEN).context("truncated section table")
    };
    let contents = |header: &[u8]| -> Result<&[u8]> {
        field(bytes, le_usize(header, 24)?, le_usize(header, 32)?).context("section outside the object")
    };
    if names_index >= section_count {
        bail!("section name table is missing");
    }
    let names = contents(header(names_index)?)?;
    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let header = header(index)?;
        sections.push(Section {
            name: elf_string(names, le_u32(header, 0)? as usize)?,
            kind: le_u32(header, 4)?,
            data: contents(header)?,
            link: le_u32(header, 40)? as usize,
            info: le_u32(header, 44)? as usize,
        });
    }

    let mut programs: BTreeMap<&str, Vec<Insn>> = BTreeMap::new();
    let mut license = None;
    let mut symbols = None;
    let (mut has_policy, mut has_map) = (false, false);
    for (index, section) in sections.iter().enumerate() {
        match (section.kind, section.name) {
            (SHT_NULL, _) | (SHT_STRTAB, _) | (SHT_LLVM_ADDRSIG, _) | (SHT_REL, _) => {}
            (SHT_SYMTAB, _) => {
                if symbols.replace(index).is_some() {
                    bail!("more than one symbol table");
                }
            }
            // The compiler always emits `.text`; every function here lives in a named section.
            (SHT_PROGBITS, ".text") if section.data.is_empty() => {}
            (SHT_PROGBITS, ".rodata") => {
                if section.data.len() != layout::LEN {
                    bail!(
                        "the object's policy is {} bytes, this agent writes {}",
                        section.data.len(),
                        layout::LEN
                    );
                }
                has_policy = true;
            }
            (SHT_PROGBITS, "maps") => {
                let expected = [
                    BPF_MAP_TYPE_LRU_HASH,
                    RESOLVED_KEY_LEN,
                    RESOLVED_VALUE_LEN,
                    RESOLVED_MAP_ENTRIES,
                    0,
                ];
                let expected: Vec<u8> = expected.iter().flat_map(|field| field.to_le_bytes()).collect();
                if section.data != expected {
                    bail!("the object's resolved-address map is not the one this agent creates");
                }
                has_map = true;
            }
            (SHT_PROGBITS, "license") => {
                license = Some(
                    std::ffi::CStr::from_bytes_with_nul(section.data)
                        .context("malformed license section")?
                        .to_owned(),
                );
            }
            (SHT_PROGBITS, name) if name.starts_with(PROGRAM_SECTION) => {
                if section.data.is_empty() || section.data.len() % 8 != 0 {
                    bail!("program {name} is not a whole number of instructions");
                }
                let insns = section
                    .data
                    .chunks_exact(8)
                    .map(|raw| Insn {
                        code: raw[0],
                        regs: raw[1],
                        off: i16::from_le_bytes([raw[2], raw[3]]),
                        imm: i32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
                    })
                    .collect();
                if programs.insert(&name[PROGRAM_SECTION.len()..], insns).is_some() {
                    bail!("program {name} appears twice in the object");
                }
            }
            (_, name) => bail!("unexpected section {name:?} in the object"),
        }
    }
    if !has_policy || !has_map {
        bail!("the object has no policy or no resolved-address map");
    }
    let symbols = &sections[symbols.context("the object has no symbol table")?];
    let symbol_names = sections.get(symbols.link).context("symbol names are missing")?.data;

    for relocations in sections.iter().filter(|section| section.kind == SHT_REL) {
        let target = sections.get(relocations.info).context("relocations for a missing section")?;
        let name = target.name.strip_prefix(PROGRAM_SECTION).with_context(|| {
            format!("relocations for {:?}, which is not a program", target.name)
        })?;
        let insns = programs.get_mut(name).context("relocations for a missing program")?;
        if sections.get(relocations.link).map(|section| section.kind) != Some(SHT_SYMTAB) {
            bail!("relocations of {name} name no symbol table");
        }
        if relocations.data.len() % ELF_REL_LEN != 0 {
            bail!("malformed relocations for {name}");
        }
        for entry in relocations.data.chunks_exact(ELF_REL_LEN) {
            let offset = le_usize(entry, 0)?;
            let info = le_u64(entry, 8)?;
            if info as u32 != R_BPF_64_64 {
                bail!("unsupported relocation type {} in {name}", info as u32);
            }
            let symbol = symbols
                .data
                .get((info >> 32) as usize * ELF_SYMBOL_LEN..)
                .and_then(|rest| rest.get(..ELF_SYMBOL_LEN))
                .context("relocation against a missing symbol")?;
            let symbol_name = elf_string(symbol_names, le_u32(symbol, 0)? as usize)?;
            let defined_in = sections
                .get(usize::from(le_u16(symbol, 6)?))
                .with_context(|| format!("symbol {symbol_name} is not defined in the object"))?;
            let value = le_u64(symbol, 8)?;

            if offset % 8 != 0 || offset / 8 + 1 >= insns.len() {
                bail!("relocation outside {name}");
            }
            let at = offset / 8;
            if insns[at].code != OP_LD_IMM64 || insns[at].src() != 0 {
                bail!("relocation in {name} is not on a 64-bit load");
            }
            // The second slot holds only the offset's upper half, zero inside the policy.
            if insns[at + 1] != (Insn { code: 0, regs: 0, off: 0, imm: 0 }) {
                bail!("relocation in {name} is on a malformed 64-bit load");
            }
            // The first slot's immediate is the offset from the symbol.
            let addend = u64::from(insns[at].imm as u32);
            match defined_in.name {
                ".rodata" => {
                    let at_value = value
                        .checked_add(addend)
                        .filter(|at_value| *at_value < layout::LEN as u64)
                        .with_context(|| format!("{name} reads outside the policy"))?;
                    insns[at].regs |= BPF_PSEUDO_MAP_IDX_VALUE << 4;
                    insns[at].imm = POLICY_MAP_INDEX;
                    insns[at + 1].imm = at_value as i32;
                }
                "maps" => {
                    if value != 0 || addend != 0 {
                        bail!("{name} refers into the resolved-address map definition");
                    }
                    insns[at].regs |= BPF_PSEUDO_MAP_IDX << 4;
                    insns[at].imm = RESOLVED_MAP_INDEX;
                }
                other => bail!("{name} refers to {symbol_name} in {other:?}"),
            }
        }
    }

    for (name, insns) in &programs {
        let mut index = 0;
        while index < insns.len() {
            let insn = insns[index];
            match insn.code {
                // No 64-bit constants in the source: an unrelocated load is a missed map reference.
                OP_LD_IMM64 => {
                    if insn.src() != BPF_PSEUDO_MAP_IDX && insn.src() != BPF_PSEUDO_MAP_IDX_VALUE {
                        bail!("{name} has an unresolved 64-bit load at instruction {index}");
                    }
                    index += 1;
                }
                OP_CALL => {
                    let helper = insn.src() == 0
                        && (insn.imm == BPF_FUNC_MAP_LOOKUP_ELEM || insn.imm == BPF_FUNC_KTIME_GET_NS);
                    if !helper {
                        bail!("{name} makes an unexpected call at instruction {index}");
                    }
                }
                _ => {}
            }
            index += 1;
        }
    }

    let mut take = |name: &str| {
        programs.remove(name).with_context(|| format!("the object has no {name} program"))
    };
    let read = Programs {
        sock_create: take("sock_create")?,
        outbound4: take("outbound4")?,
        outbound6: take("outbound6")?,
        bind4: take("bind4")?,
        bind6: take("bind6")?,
        egress: take("egress")?,
        license: license.context("the object has no license")?,
    };
    if let Some(name) = programs.keys().next() {
        bail!("unexpected program {name} in the object");
    }
    Ok(read)
}

// ---------------------------------------------------------------------------------------------
// Loading and attaching
// Every failure is returned: an attach that silently does nothing leaves a container unenforced.
// ---------------------------------------------------------------------------------------------

/// `union bpf_attr` is 168 bytes; the prog-load fields used end at byte 152 with `fd_array_cnt`,
/// which needs Linux 6.14+.
const BPF_ATTR_SIZE: usize = 160;

/// `bpf(2)` commands, from `enum bpf_cmd`.
const BPF_MAP_CREATE: u64 = 0;
const BPF_MAP_UPDATE_ELEM: u64 = 2;
const BPF_PROG_LOAD: u64 = 5;
const BPF_PROG_ATTACH: u64 = 8;
const BPF_PROG_QUERY: u64 = 16;
const BPF_MAP_FREEZE: u64 = 22;

/// # Safety
/// Every pointer stored in `attr` must be valid for what `command` does with it.
unsafe fn bpf(command: u64, attr: &mut [u64; BPF_ATTR_SIZE / 8]) -> std::io::Result<i64> {
    let rc = libc::syscall(libc::SYS_bpf, command, attr.as_mut_ptr(), BPF_ATTR_SIZE);
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(rc)
}

fn create_map(
    map_type: u32,
    key_len: u32,
    value_len: u32,
    entries: u32,
    flags: u32,
) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut attr = [0u64; BPF_ATTR_SIZE / 8];
    // map_type (u32) at 0, key_size (u32) at 4, value_size (u32) at 8, max_entries (u32) at 12,
    // map_flags (u32) at 16.
    attr[0] = u64::from(map_type) | (u64::from(key_len) << 32);
    attr[1] = u64::from(value_len) | (u64::from(entries) << 32);
    attr[2] = u64::from(flags);
    let fd = unsafe { bpf(BPF_MAP_CREATE, &mut attr) }?;
    use std::os::fd::FromRawFd;
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) })
}

/// The map the DNS filter publishes resolved addresses into.
pub fn create_resolved_map() -> std::io::Result<std::os::fd::OwnedFd> {
    create_map(
        BPF_MAP_TYPE_LRU_HASH,
        RESOLVED_KEY_LEN,
        RESOLVED_VALUE_LEN,
        RESOLVED_MAP_ENTRIES,
        0,
    )
}

/// A one-element map holding `policy`, read-only to programs and frozen, so no process can
/// update it afterwards.
fn create_policy_map(policy: &[u8]) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let len = u32::try_from(policy.len()).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let map = create_map(BPF_MAP_TYPE_ARRAY, 4, len, 1, BPF_F_RDONLY_PROG)?;
    let key = 0u32;
    let mut attr = [0u64; BPF_ATTR_SIZE / 8];
    // map_fd (u32) at 0, key (u64) at 8, value (u64) at 16, flags (u64) at 24.
    attr[0] = u64::from(map.as_raw_fd() as u32);
    attr[1] = &key as *const u32 as u64;
    attr[2] = policy.as_ptr() as u64;
    unsafe { bpf(BPF_MAP_UPDATE_ELEM, &mut attr) }?;
    let mut attr = [0u64; BPF_ATTR_SIZE / 8];
    attr[0] = u64::from(map.as_raw_fd() as u32);
    unsafe { bpf(BPF_MAP_FREEZE, &mut attr) }?;
    Ok(map)
}

/// The maps every program of a container refers to, in `fd_array` order.
struct ProgramMaps {
    resolved: std::sync::Arc<std::os::fd::OwnedFd>,
    policy: std::os::fd::OwnedFd,
}

/// # Safety
/// `insns`, `license` and `fds` must outlive the call, which the borrows guarantee.
unsafe fn prog_load(
    prog_type: u32,
    expected_attach_type: u32,
    insns: &[Insn],
    license: &std::ffi::CStr,
    log: &mut [u8],
    fds: &[i32],
) -> std::io::Result<std::os::fd::OwnedFd> {
    let mut attr = [0u64; BPF_ATTR_SIZE / 8];
    // prog_type (u32) at 0, insn_cnt (u32) at 4, insns (u64) at 8, license (u64) at 16,
    // log_level (u32) at 24, log_size (u32) at 28, log_buf (u64) at 32.
    attr[0] = u64::from(prog_type);
    attr[0] |= u64::from(insns.len() as u32) << 32;
    attr[1] = insns.as_ptr() as u64;
    attr[2] = license.as_ptr() as u64;
    if !log.is_empty() {
        attr[3] = 1 | (u64::try_from(log.len()).unwrap_or(0) << 32);
        attr[4] = log.as_mut_ptr() as u64;
    }
    // expected_attach_type (u32) at 68. cgroup sock_addr programs must declare the hook at load
    // time, because the verifier checks context access against the attach type.
    attr[8] |= u64::from(expected_attach_type) << 32;
    // fd_array (aligned u64) at byte 120 = word 15; fd_array_cnt (u32) at byte 148 = word 18,
    // high half. The programs' map references index this array.
    attr[15] = fds.as_ptr() as u64;
    attr[18] |= u64::from(fds.len() as u32) << 32;
    let fd = bpf(BPF_PROG_LOAD, &mut attr)?;
    use std::os::fd::FromRawFd;
    Ok(std::os::fd::OwnedFd::from_raw_fd(fd as i32))
}

/// # Safety
/// `cgroup` must be an open cgroup directory fd.
unsafe fn prog_attach(prog_fd: i32, cgroup: i32, attach_type: u32) -> std::io::Result<()> {
    let mut attr = [0u64; BPF_ATTR_SIZE / 8];
    // target_fd (u32) at 0, attach_bpf_fd (u32) at 4, attach_type (u32) at 8, attach_flags at 12.
    attr[0] = u64::from(cgroup as u32) | (u64::from(prog_fd as u32) << 32);
    attr[1] = u64::from(attach_type);
    // attach_flags stays 0: no delegation or ancestor override.
    bpf(BPF_PROG_ATTACH, &mut attr)?;
    Ok(())
}

/// Refuse a cgroup another container's programs are attached to: a second attach would replace
/// them. The host picks `cgroupsPath`, so it could otherwise leave a container unenforced.
pub fn check_cgroup_unshared<'a>(
    cgroup_dir: &Path,
    attached: impl IntoIterator<Item = (&'a String, &'a Vec<Attached>)>,
) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let dir = std::fs::metadata(cgroup_dir)
        .with_context(|| format!("reading cgroup {}", cgroup_dir.display()))?;
    for (container, programs) in attached {
        for program in programs {
            let identity = program
                .cgroup_identity()
                .with_context(|| format!("reading the cgroup of container {container}"))?;
            if identity == (dir.dev(), dir.ino()) {
                bail!(
                    "cgroup {} already enforces the network policy of container {container}; \
                     enforced containers cannot share a cgroup",
                    cgroup_dir.display()
                );
            }
        }
    }
    Ok(())
}

/// An attached program and its descriptors. Nothing detaches it: the program stays until the
/// cgroup is released, so a process outliving its container stays enforced.
#[derive(Debug)]
pub struct Attached {
    prog_fd: std::os::fd::OwnedFd,
    cgroup_fd: std::os::fd::OwnedFd,
    /// Held so the map stays open while the program is attached.
    _map: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
}

impl Attached {
    /// Consume the guard and close both descriptors; the program stays attached (see `Attached`).
    pub fn detach(self) {}

    /// Device and inode of the cgroup directory.
    fn cgroup_identity(&self) -> std::io::Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::File::from(self.cgroup_fd.try_clone()?).metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }

    pub fn resolved_map(&self) -> Option<std::sync::Arc<std::os::fd::OwnedFd>> {
        self._map.clone()
    }
}

/// Programs attached directly to `cgroup` (`BPF_PROG_QUERY`).
fn attached_program_count(cgroup: &std::fs::File, attach_type: u32) -> std::io::Result<u32> {
    use std::os::fd::AsRawFd;
    let mut attr = [0u64; BPF_ATTR_SIZE / 8];
    // target_fd (u32) at 0, attach_type (u32) at 4, query_flags at 8, attach_flags at 12,
    // prog_ids (u64) at 16, prog_cnt (u32) at 24. A null prog_ids asks for the count only.
    attr[0] = u64::from(cgroup.as_raw_fd() as u32) | (u64::from(attach_type) << 32);
    unsafe { bpf(BPF_PROG_QUERY, &mut attr) }?;
    Ok(attr[3] as u32)
}

const VERIFIER_LOG_LEN: usize = 1 << 20;

fn attach(
    insns: &[Insn],
    license: &std::ffi::CStr,
    prog_type: u32,
    attach_type: u32,
    cgroup_dir: &Path,
    maps: &ProgramMaps,
    held: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
) -> Result<Attached> {
    use std::os::fd::AsRawFd;
    if insns.is_empty() {
        bail!("refusing to attach an empty program");
    }
    // In `fd_array` order: RESOLVED_MAP_INDEX, POLICY_MAP_INDEX.
    let fds = [maps.resolved.as_raw_fd(), maps.policy.as_raw_fd()];
    // The log is long with loops: load without one and repeat only a refused load to read it.
    let prog_fd = match unsafe { prog_load(prog_type, attach_type, insns, license, &mut [], &fds) } {
        Ok(fd) => fd,
        Err(refused) => {
            let mut log = vec![0u8; VERIFIER_LOG_LEN];
            let again = unsafe { prog_load(prog_type, attach_type, insns, license, &mut log, &fds) };
            match again {
                Ok(fd) => fd,
                Err(e) => {
                    let log = String::from_utf8_lossy(&log);
                    let log = log.trim_matches('\0').trim();
                    // An overflowing log turns the error into ENOSPC, so report the first one too.
                    bail!("loading {prog_type} program: {refused} ({e} with a log); verifier: {log}");
                }
            }
        }
    };
    let cgroup_file = std::fs::OpenOptions::new()
        .read(true)
        .open(cgroup_dir)
        .with_context(|| format!("opening cgroup {}", cgroup_dir.display()))?;
    let cgroup_fd: std::os::fd::OwnedFd = cgroup_file.into();
    unsafe { prog_attach(prog_fd.as_raw_fd(), cgroup_fd.as_raw_fd(), attach_type) }
        .with_context(|| format!("attaching program to {}", cgroup_dir.display()))?;
    Ok(Attached {
        prog_fd,
        cgroup_fd,
        _map: held,
    })
}

/// Attach every program a container needs; on error the container must not start. A cgroup that
/// already has programs is refused: they may belong to a removed container's surviving processes.
pub fn enforce(
    policy: &ContainerPolicy,
    cgroup_dir: &Path,
    reserved_ports: &BTreeSet<u16>,
    resolved_map: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
) -> Result<Vec<Attached>> {
    let cgroup = std::fs::File::open(cgroup_dir)
        .with_context(|| format!("opening cgroup {}", cgroup_dir.display()))?;
    let existing = attached_program_count(&cgroup, BPF_CGROUP_INET4_CONNECT)
        .with_context(|| format!("querying the programs of cgroup {}", cgroup_dir.display()))?;
    if existing > 0 {
        bail!(
            "cgroup {} already has network-policy programs attached; a container cannot take over \
             another's cgroup",
            cgroup_dir.display()
        );
    }
    let programs = programs()?;
    let encoded = ProgramPolicy::new(policy, reserved_ports)?.encode()?;

    // The sandbox shares one resolved map; only the programs that consult it hold a reference.
    let consults_resolved = policy.mode == Mode::EgressAllowlist && policy.destination_axis();
    if consults_resolved && resolved_map.is_none() {
        bail!("egress-allowlist needs the resolved-address map");
    }
    let held = if consults_resolved { resolved_map.clone() } else { None };
    // The kernel wants a real map behind every program's reference, consulted or not.
    let resolved = match resolved_map {
        Some(map) => map,
        None => std::sync::Arc::new(
            create_resolved_map().context("creating a resolved-address map")?,
        ),
    };
    let maps = ProgramMaps {
        resolved,
        policy: create_policy_map(&encoded).context("creating the policy map")?,
    };

    let mut attached = Vec::new();
    let mut install = |program: &[Insn], prog_type, hook| -> Result<()> {
        attached.push(attach(
            program,
            &programs.license,
            prog_type,
            hook,
            cgroup_dir,
            &maps,
            held.clone(),
        )?);
        Ok(())
    };
    install(&programs.sock_create, BPF_PROG_TYPE_CGROUP_SOCK, BPF_CGROUP_INET_SOCK_CREATE)?;
    // The sendmsg hooks run the connect programs, so UDP is governed like TCP.
    install(&programs.outbound4, BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_CONNECT)?;
    install(&programs.outbound6, BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_CONNECT)?;
    install(&programs.outbound4, BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP4_SENDMSG)?;
    install(&programs.outbound6, BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_UDP6_SENDMSG)?;
    install(&programs.bind4, BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET4_BIND)?;
    install(&programs.bind6, BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_INET6_BIND)?;
    // The socket-level hooks cannot see a source route; the packet-level backstop drops it.
    install(&programs.egress, BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS)?;
    drop(install);
    Ok(attached)
}

// ---------------------------------------------------------------------------------------------
// DNS name filter
// Only allowed names are forwarded, as rebuilt queries; their addresses go into the resolved map.
// ---------------------------------------------------------------------------------------------

const DNS_HEADER_LEN: usize = 12;
const DNS_RCODE_REFUSED: u8 = 5;
pub const DNS_MAX_MESSAGE: usize = 4096;
const DNS_MAX_ANSWERS: u16 = 64;

/// The lowercased QNAME of a single-question message, and where its question ends.
fn parse_question(message: &[u8]) -> Option<(String, usize)> {
    if message.len() < DNS_HEADER_LEN || message.len() > DNS_MAX_MESSAGE {
        return None;
    }
    if u16::from_be_bytes([message[4], message[5]]) != 1 {
        return None;
    }
    let mut labels = Vec::new();
    let mut offset = DNS_HEADER_LEN;
    loop {
        let length = *message.get(offset)? as usize;
        offset += 1;
        if length == 0 {
            break;
        }
        // Length values 0xc0 and above are compression/reserved, not literal labels.
        if length > 63 {
            return None;
        }
        let label = message.get(offset..offset + length)?;
        labels.push(std::str::from_utf8(label).ok()?);
        offset += length;
        if labels.len() > 127 {
            return None;
        }
    }
    if labels.is_empty() {
        return None;
    }
    if message.len() < offset + 4 {
        return None;
    }
    Some((labels.join(".").to_ascii_lowercase(), offset + 4))
}

fn parse_query(message: &[u8]) -> Option<(String, usize)> {
    let parsed = parse_question(message)?;
    // Standard query only, QR=0, IN class, and A or AAAA questions.
    if message[2] & 0xfe != 0 {
        return None;
    }
    let end = parsed.1;
    let qtype = u16::from_be_bytes([message[end - 4], message[end - 3]]);
    let qclass = u16::from_be_bytes([message[end - 2], message[end - 1]]);
    if qclass != 1 || !matches!(qtype, 1 | 28) {
        return None;
    }
    Some(parsed)
}

pub fn parse_qname(message: &[u8]) -> Option<String> {
    parse_query(message).map(|(name, _)| name)
}

pub fn response_matches_query(query: &[u8], response: &[u8]) -> bool {
    let Some((_, query_end)) = parse_query(query) else {
        return false;
    };
    if response.len() < DNS_HEADER_LEN
        || response.len() > DNS_MAX_MESSAGE
        || response[0..2] != query[0..2]
        || response[2] & 0x80 == 0
        || response[2] & 0x78 != query[2] & 0x78
    {
        return false;
    }
    let Some((_, response_end)) = parse_question(response) else {
        return false;
    };
    response_end == query_end && response[12..response_end] == query[12..query_end]
}

/// Addresses of the queried type on the CNAME chain from the queried name, each with the
/// shortest TTL along the chain. Records for other owners are ignored; malformed input yields none.
pub fn answer_addresses(query: &[u8], response: &[u8]) -> Vec<([u8; 16], u32)> {
    chain_addresses(query, response).unwrap_or_default()
}

fn chain_addresses(query: &[u8], response: &[u8]) -> Option<Vec<([u8; 16], u32)>> {
    let (qname, query_end) = parse_query(query)?;
    let qtype = u16::from_be_bytes([query[query_end - 4], query[query_end - 3]]);
    let (_, mut at) = parse_question(response)?;
    let count = u16::from_be_bytes([*response.get(6)?, *response.get(7)?]);
    let mut addresses: Vec<(String, [u8; 16], u32)> = Vec::new();
    let mut aliases: Vec<(String, String, u32)> = Vec::new();
    for _ in 0..count.min(DNS_MAX_ANSWERS) {
        let (owner, next) = read_name(response, at)?;
        let header = response.get(next..next + 10)?;
        let rtype = u16::from_be_bytes([header[0], header[1]]);
        let class = u16::from_be_bytes([header[2], header[3]]);
        let ttl = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
        let rdlength = usize::from(u16::from_be_bytes([header[8], header[9]]));
        let rdata = next + 10;
        let data = response.get(rdata..rdata + rdlength)?;
        match (class, rtype, rdlength) {
            (1, 1, 4) if qtype == 1 => {
                let octets = <[u8; 4]>::try_from(data).ok()?;
                addresses.push((owner, resolved_key(IpAddr::from(octets)), ttl));
            }
            (1, 28, 16) if qtype == 28 => {
                addresses.push((owner, <[u8; 16]>::try_from(data).ok()?, ttl))
            }
            (1, 5, _) => {
                let (target, end) = read_name(response, rdata)?;
                if end != rdata + rdlength {
                    return None;
                }
                aliases.push((owner, target, ttl));
            }
            _ => {}
        }
        at = rdata + rdlength;
    }
    // Each pass adds a name or stops, so this terminates.
    let mut chain = vec![qname];
    loop {
        let before = chain.len();
        for (owner, target, _) in &aliases {
            if chain.contains(owner) && !chain.contains(target) {
                chain.push(target.clone());
            }
        }
        if chain.len() == before {
            break;
        }
    }
    // An address is only as fresh as the shortest-lived link of the chain that led to it.
    let chain_ttl = aliases
        .iter()
        .filter(|(owner, _, _)| chain.contains(owner))
        .map(|(_, _, ttl)| *ttl)
        .min()
        .unwrap_or(u32::MAX);
    Some(
        addresses
            .into_iter()
            .filter(|(owner, _, _)| chain.contains(owner))
            .map(|(_, key, ttl)| (key, ttl.min(chain_ttl)))
            .collect(),
    )
}

/// A possibly compressed name at `at`, lowercased without the trailing dot, and the offset past
/// it. Pointers must point strictly backwards, which bounds the walk.
fn read_name(message: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut resume = None;
    let mut length = 0usize;
    loop {
        let byte = *message.get(at)?;
        match byte & 0xc0 {
            0x00 if byte == 0 => return Some((labels.join("."), resume.unwrap_or(at + 1))),
            0x00 => {
                let label = message.get(at + 1..at + 1 + usize::from(byte))?;
                length += label.len() + 1;
                if length > 255 || label.contains(&b'.') {
                    return None;
                }
                labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
                at += 1 + label.len();
            }
            0xc0 => {
                let pointer = usize::from(u16::from_be_bytes([byte, *message.get(at + 1)?]) & 0x3fff);
                if pointer >= at {
                    return None;
                }
                resume.get_or_insert(at + 2);
                at = pointer;
            }
            _ => return None,
        }
    }
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
    Some(())
}

/// The query sent upstream: only the id, the RD bit and the lowercased question, so an allowed
/// name cannot carry arbitrary bytes to the resolver.
pub fn upstream_query(query: &[u8]) -> Option<Vec<u8>> {
    let (name, end) = parse_query(query)?;
    let mut out = Vec::with_capacity(DNS_HEADER_LEN + name.len() + 6);
    out.extend_from_slice(&query[0..2]);
    out.extend_from_slice(&[query[2] & 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(&mut out, &name)?;
    out.extend_from_slice(&query[end - 4..end]);
    Some(out)
}

/// The upstream response with the client's id and question spelling. The questions differ only
/// in case, so every compression pointer still lands where it did.
pub fn client_response(query: &[u8], response: &[u8]) -> Option<Vec<u8>> {
    let (_, query_end) = parse_query(query)?;
    let (_, response_end) = parse_question(response)?;
    if response_end != query_end {
        return None;
    }
    let mut out = response.to_vec();
    out[0..2].copy_from_slice(&query[0..2]);
    out[DNS_HEADER_LEN..query_end].copy_from_slice(&query[DNS_HEADER_LEN..query_end]);
    Some(out)
}

/// The resolved-map key: the IPv6 address, or `::ffff:a.b.c.d`. Must match the key
/// `net-policy.bpf.c` builds (`destination4_allowed`, `destination6_allowed`).
pub fn resolved_key(addr: IpAddr) -> [u8; 16] {
    match addr {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    }
}

/// Nanoseconds on CLOCK_MONOTONIC, the clock `bpf_ktime_get_ns` reads.
fn monotonic_ns() -> u64 {
    let mut now = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    now.tv_sec as u64 * 1_000_000_000 + now.tv_nsec as u64
}

/// Publish addresses so the egress programs admit them until their clamped TTL. Best effort: a
/// failure only leaves the name unreachable, which fails closed.
pub fn publish_resolved(map_fd: i32, addresses: &[([u8; 16], u32)]) {
    let now = monotonic_ns();
    for (key, ttl) in addresses {
        let lifetime = u64::from((*ttl).clamp(RESOLVED_MIN_TTL, RESOLVED_MAX_TTL));
        let expiry = (now + lifetime * 1_000_000_000).to_ne_bytes();
        let mut attr = [0u64; BPF_ATTR_SIZE / 8];
        // map_fd (u32) at 0, key (u64) at 8, value (u64) at 16, flags (u64) at 24.
        attr[0] = u64::from(map_fd as u32);
        attr[1] = key.as_ptr() as u64;
        attr[2] = expiry.as_ptr() as u64;
        // BPF_ANY: insert or replace.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_bpf,
                2, /* BPF_MAP_UPDATE_ELEM */
                attr.as_mut_ptr(),
                BPF_ATTR_SIZE,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            eprintln!("podvm: recording resolved address failed: {error}");
        }
    }
}

/// Case-insensitive, ignoring a trailing dot.
pub fn name_allowed(allow: &BTreeSet<String>, qname: &str) -> bool {
    allow.contains(&normalized_dns_name(qname))
}

/// A `REFUSED` response echoing the question, so the client sees a refusal, not a timeout.
pub fn refused_response(query: &[u8]) -> Vec<u8> {
    if query.len() < DNS_HEADER_LEN {
        return Vec::new();
    }
    // A malformed question is not echoed: header only, with QDCOUNT=0.
    let question_end = parse_question(query)
        .map(|(_, end)| end)
        .unwrap_or(DNS_HEADER_LEN);
    let mut response = query[..question_end].to_vec();
    response[2] = 0x80 | (query[2] & 0x79); // QR, original opcode and RD
    response[3] = 0x80 | DNS_RCODE_REFUSED;
    if question_end == DNS_HEADER_LEN {
        response[4..6].copy_from_slice(&0u16.to_be_bytes());
    }
    response[6..8].copy_from_slice(&0u16.to_be_bytes());
    response[8..10].copy_from_slice(&0u16.to_be_bytes());
    response[10..12].copy_from_slice(&0u16.to_be_bytes());
    response
}

pub fn should_forward(allow: &BTreeSet<String>, query: &[u8]) -> bool {
    match parse_qname(query) {
        Some(qname) => name_allowed(allow, &qname),
        None => false,
    }
}

#[derive(Debug)]
pub struct DnsFilter {
    handle: tokio::task::JoinHandle<()>,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl DnsFilter {
    /// Wait until every worker has released its socket, so the port can be bound again at once.
    pub async fn stop(mut self) {
        let _ = self.shutdown.send(true);
        let _ = (&mut self.handle).await;
    }
}

impl Drop for DnsFilter {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        // Best effort; `stop()` waits for the workers.
        self.handle.abort();
    }
}

/// Serve the filter on the stub address over UDP and TCP. The tasks own `resolved_map`, so it
/// stays open while they can publish.
pub async fn start_dns_filter(
    allow: BTreeSet<String>,
    upstreams: Vec<SocketAddr>,
    resolved_map: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
) -> Result<DnsFilter> {
    if upstreams.is_empty() || upstreams.len() > 8 {
        bail!("the DNS filter needs between 1 and 8 upstream resolvers");
    }
    let addr = SocketAddr::from(([127, 0, 0, 53], DNS_STUB_PORT));
    let udp = tokio::net::UdpSocket::bind(addr)
        .await
        .with_context(|| format!("binding DNS filter UDP {addr}"))?;
    let tcp = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding DNS filter TCP {addr}"))?;
    let allow = std::sync::Arc::new(allow);
    let upstreams = std::sync::Arc::new(upstreams);
    let (shutdown, stop_signal) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(async move {
        // Dropping a JoinSet only requests cancellation, so both loops drain their workers first.
        let (_, _) = tokio::join!(
            udp_loop(udp, allow.clone(), upstreams.clone(), stop_signal.clone(), resolved_map.clone()),
            tcp_loop(tcp, allow, upstreams, stop_signal, resolved_map),
        );
    });
    Ok(DnsFilter { handle, shutdown })
}

/// Cached answers per transport; keys come only from allowed names, so this is rarely reached.
const DNS_CACHE_ENTRIES: usize = 256;

/// Forwarding state for one transport, keyed by the rebuilt query without its id.
#[derive(Default)]
struct ForwardState {
    in_flight: BTreeMap<Vec<u8>, std::sync::Arc<tokio::sync::OnceCell<Option<Vec<u8>>>>>,
    /// Cached answers and their expiry.
    answers: BTreeMap<Vec<u8>, (Vec<u8>, std::time::Instant)>,
}

type Forwarding = std::sync::Arc<std::sync::Mutex<ForwardState>>;

fn cached_answer(forwarding: &Forwarding, upstream: &[u8]) -> Option<Vec<u8>> {
    let state = forwarding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    state
        .answers
        .get(&upstream[2..])
        .filter(|(_, expiry)| *expiry > std::time::Instant::now())
        .map(|(answer, _)| answer.clone())
}

/// Shortest record TTL, capped at `RESOLVED_MAX_TTL`; `None` for truncated, empty or error answers.
fn cache_ttl(response: &[u8]) -> Option<u32> {
    if response.len() < DNS_HEADER_LEN || response[2] & 0x02 != 0 || response[3] & 0x0f != 0 {
        return None;
    }
    let (_, mut at) = parse_question(response)?;
    let count = u16::from_be_bytes([response[6], response[7]]);
    if count == 0 || count > DNS_MAX_ANSWERS {
        return None;
    }
    let mut ttl = RESOLVED_MAX_TTL;
    for _ in 0..count {
        let (_, next) = read_name(response, at)?;
        let header = response.get(next..next + 10)?;
        ttl = ttl.min(u32::from_be_bytes([header[4], header[5], header[6], header[7]]));
        at = next + 10 + usize::from(u16::from_be_bytes([header[8], header[9]]));
    }
    response.get(..at)?;
    (ttl > 0).then(|| ttl)
}

/// Answer from the cache, wait for an identical question in flight, or forward with `forward`.
async fn forward_merged<F, Fut>(forwarding: &Forwarding, upstream: Vec<u8>, forward: F) -> Option<Vec<u8>>
where
    F: FnOnce(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Option<Vec<u8>>>,
{
    if let Some(answer) = cached_answer(forwarding, &upstream) {
        return Some(answer);
    }
    // `upstream_query` normalizes everything but the id, so the rest identifies the question.
    let key = upstream[2..].to_vec();
    let cell = forwarding
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .in_flight
        .entry(key.clone())
        .or_default()
        .clone();
    // If the task running the request is cancelled, a waiting one runs its own instead.
    let response = cell.get_or_init(|| forward(upstream)).await.clone();
    let mut state = forwarding.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if state.in_flight.get(&key).map_or(false, |current| std::sync::Arc::ptr_eq(current, &cell)) {
        state.in_flight.remove(&key);
        if let Some((answer, ttl)) = response.as_ref().and_then(|answer| Some((answer, cache_ttl(answer)?))) {
            let now = std::time::Instant::now();
            state.answers.retain(|_, (_, expiry)| *expiry > now);
            if state.answers.len() < DNS_CACHE_ENTRIES {
                state.answers.insert(key, (answer.clone(), now + Duration::from_secs(u64::from(ttl))));
            }
        }
    }
    response
}

async fn udp_loop(
    socket: tokio::net::UdpSocket,
    allow: std::sync::Arc<BTreeSet<String>>,
    upstreams: std::sync::Arc<Vec<SocketAddr>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    resolved_map: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
) {
    use std::os::fd::AsRawFd;
    // dnsmasq's default --dns-forward-max.
    const MAX_IN_FLIGHT: usize = 150;
    let socket = std::sync::Arc::new(socket);
    let forwarding = Forwarding::default();
    let mut tasks = tokio::task::JoinSet::new();
    let mut buf = vec![0u8; DNS_MAX_MESSAGE];
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            Some(_) = tasks.join_next() => {},
            received = socket.recv_from(&mut buf) => {
                let (len, peer) = match received {
                    Ok(received) => received,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let query = buf[..len].to_vec();
                let Some(upstream) = should_forward(&allow, &query)
                    .then(|| upstream_query(&query))
                    .flatten()
                else {
                    let refusal = refused_response(&query);
                    if !refusal.is_empty() {
                        let _ = socket.send_to(&refusal, peer).await;
                    }
                    continue;
                };
                // Cached answers need no slot, so a burst on one name cannot hold up other clients.
                if let Some(response) = cached_answer(&forwarding, &upstream)
                    .and_then(|answer| client_response(&query, &answer))
                {
                    if let Some(fd) = &resolved_map {
                        publish_resolved(fd.as_raw_fd(), &answer_addresses(&query, &response));
                    }
                    let _ = socket.send_to(&response, peer).await;
                    continue;
                }
                // When full, refuse rather than stop reading, so cached answers keep flowing.
                if tasks.len() >= MAX_IN_FLIGHT {
                    let refusal = refused_response(&query);
                    if !refusal.is_empty() {
                        let _ = socket.send_to(&refusal, peer).await;
                    }
                    continue;
                }
                let client = socket.clone();
                let upstreams = upstreams.clone();
                let resolved_map = resolved_map.clone();
                let forwarding = forwarding.clone();
                tasks.spawn(async move {
                    let response = forward_merged(&forwarding, upstream, move |upstream| async move {
                        forward_udp(&upstream, &upstreams).await
                    })
                    .await
                    .and_then(|response| client_response(&query, &response))
                        .unwrap_or_else(|| refused_response(&query));
                    if !response.is_empty() {
                        // Publish before replying, so the address is already reachable.
                        if let Some(fd) = resolved_map {
                            publish_resolved(fd.as_raw_fd(), &answer_addresses(&query, &response));
                        }
                        let _ = client.send_to(&response, peer).await;
                    }
                });
            }
        }
    }
    tasks.shutdown().await;
}

async fn forward_udp(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    for upstream in upstreams {
        let bind = if upstream.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let Ok(socket) = tokio::net::UdpSocket::bind(bind).await else {
            continue;
        };
        // A connected UDP socket accepts datagrams only from this resolver.
        if socket.connect(upstream).await.is_err() || socket.send(query).await.is_err() {
            continue;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        let mut buf = vec![0u8; DNS_MAX_MESSAGE];
        loop {
            let Ok(Ok(len)) = tokio::time::timeout_at(deadline, socket.recv(&mut buf)).await else {
                break;
            };
            if response_matches_query(query, &buf[..len]) {
                buf.truncate(len);
                return Some(buf);
            }
            // Ignore transaction/question mismatches until this resolver's deadline.
        }
    }
    None
}

async fn tcp_loop(
    listener: tokio::net::TcpListener,
    allow: std::sync::Arc<BTreeSet<String>>,
    upstreams: std::sync::Arc<Vec<SocketAddr>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    resolved_map: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
) {
    // dnsmasq's default --dns-forward-max.
    const MAX_CLIENTS: usize = 150;
    // Separate from the UDP state: a TCP query is often the retry of a truncated UDP answer.
    let forwarding = Forwarding::default();
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        if tasks.len() >= MAX_CLIENTS {
            let _ = tasks.join_next().await;
            continue;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            Some(_) = tasks.join_next() => {},
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                };
                let allow = allow.clone();
                let upstreams = upstreams.clone();
                let resolved_map = resolved_map.clone();
                let forwarding = forwarding.clone();
                tasks.spawn(async move {
                    // Half-open clients cannot retain an agent task/socket indefinitely.
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        handle_tcp(stream, allow, upstreams, resolved_map, forwarding),
                    ).await;
                });
            }
        }
    }
    tasks.shutdown().await;
}

async fn handle_tcp(
    mut stream: tokio::net::TcpStream,
    allow: std::sync::Arc<BTreeSet<String>>,
    upstreams: std::sync::Arc<Vec<SocketAddr>>,
    resolved_map: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    forwarding: Forwarding,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let len = usize::from(u16::from_be_bytes(length));
    if len == 0 || len > DNS_MAX_MESSAGE {
        return Ok(());
    }
    let mut query = vec![0u8; len];
    stream.read_exact(&mut query).await?;
    let upstream = should_forward(&allow, &query)
        .then(|| upstream_query(&query))
        .flatten();
    let response = match upstream {
        Some(upstream) => forward_merged(&forwarding, upstream, move |upstream| async move {
            forward_tcp(&upstream, &upstreams).await
        })
        .await
        .and_then(|response| client_response(&query, &response))
            .unwrap_or_else(|| refused_response(&query)),
        None => refused_response(&query),
    };
    if response.is_empty() {
        return Ok(());
    }
    if let Some(fd) = resolved_map {
        publish_resolved(fd.as_raw_fd(), &answer_addresses(&query, &response));
    }
    stream
        .write_all(&(response.len() as u16).to_be_bytes())
        .await?;
    stream.write_all(&response).await?;
    Ok(())
}

async fn forward_tcp(query: &[u8], upstreams: &[SocketAddr]) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for upstream in upstreams {
        let attempt = tokio::time::timeout(Duration::from_secs(2), async {
            let mut socket = tokio::net::TcpStream::connect(upstream).await.ok()?;
            socket
                .write_all(&(query.len() as u16).to_be_bytes())
                .await
                .ok()?;
            socket.write_all(query).await.ok()?;
            let mut length = [0u8; 2];
            socket.read_exact(&mut length).await.ok()?;
            let len = usize::from(u16::from_be_bytes(length));
            if len == 0 || len > DNS_MAX_MESSAGE {
                return None;
            }
            let mut response = vec![0u8; len];
            socket.read_exact(&mut response).await.ok()?;
            response_matches_query(query, &response).then_some(response)
        })
        .await;
        if let Ok(Some(response)) = attempt {
            return Some(response);
        }
    }
    None
}

pub fn write_resolv_conf(path: &Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path
        .parent()
        .context("resolver path has no parent directory")?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    file.write_all(format!("nameserver {DNS_STUB_ADDR}\n").as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

/// Entries are resolv.conf lines such as `nameserver 10.0.2.3`; other directives are ignored.
pub fn parse_upstreams(entries: &[String]) -> Result<Vec<SocketAddr>> {
    let mut out = Vec::new();
    for line in entries {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() || fields[0].starts_with('#') {
            continue;
        }
        if fields[0] != "nameserver" {
            continue;
        }
        if fields.len() != 2 {
            bail!("invalid nameserver record {line:?}");
        }
        let addr = if let Ok(socket) = fields[1].parse::<SocketAddr>() {
            socket
        } else {
            let ip = fields[1]
                .parse::<IpAddr>()
                .with_context(|| format!("resolver record {line:?} has no valid IP address"))?;
            SocketAddr::new(ip, 53)
        };
        if addr.port() == 0 {
            bail!("resolver record {line:?} uses port 0");
        }
        out.push(addr);
        if out.len() > 8 {
            bail!("more than 8 DNS upstreams");
        }
    }
    if out.is_empty() {
        bail!("no nameserver records in the sandbox resolver list");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;

    fn policy(json: &str) -> Result<Policy> {
        parse(json)
    }

    const VLLM: &str = r#"{
        "version": 1,
        "containers": {
            "vllm": {"mode": "loopback-only", "service_ports": [8000]},
            "attestation": {
                "mode": "egress-allowlist",
                "service_ports": [8081],
                "dns_allow": ["nras.attestation.nvidia.com"],
                "port_allow": ["443/tcp"],
                "cidr_allow": []
            }
        }
    }"#;

    #[test]
    fn parses_the_fleet_policy() {
        let parsed = policy(VLLM).expect("policy parses");
        assert_eq!(parsed.container("vllm").unwrap().mode, Mode::LoopbackOnly);
        assert_eq!(
            parsed.container("attestation").unwrap().mode,
            Mode::EgressAllowlist
        );
    }

    #[test]
    fn service_ports_accept_ranges_and_bare_numbers() {
        let ranged = VLLM.replace(
            r#""service_ports": [8000]"#,
            r#""service_ports": [8000, "9000-9002"]"#,
        );
        let parsed = policy(&ranged).expect("ranges parse");
        assert_eq!(
            parsed.container("vllm").unwrap().service_ports,
            vec![
                PortRule::tcp(PortRange::single(8000)),
                PortRule::tcp(PortRange { start: 9000, end: 9002 })
            ]
        );
        let reserved = parsed.reserved_ports();
        for port in [9000, 9001, 9002] {
            assert!(reserved.contains(&port), "port {} must be reserved", port);
        }
    }

    #[test]
    fn service_port_ranges_are_validated() {
        for (label, spec) in [
            ("inverted", r#""service_ports": ["9002-9000"]"#),
            ("overlapping", r#""service_ports": ["9000-9010", "9005-9015"]"#),
            ("non numeric", r#""service_ports": ["90o0-9010"]"#),
            ("covers dns stub", r#""service_ports": ["40-60"]"#),
            ("zero start", r#""service_ports": ["0-10"]"#),
            ("out of range", r#""service_ports": ["65530-65540"]"#),
            ("too wide", r#""service_ports": ["1024-4096"]"#),
        ] {
            let candidate = VLLM.replace(r#""service_ports": [8000]"#, spec);
            assert!(policy(&candidate).is_err(), "{} must be rejected", label);
        }
    }

    #[test]
    fn port_ranges_allow_every_port_in_the_span() {
        // 1000-2000 and 255-256 invert when byte-swapped, so a byte-order bug fails them;
        // 8000-8100 shares a high byte and passes either way.
        for (start, end) in [(1000u16, 2000u16), (255, 256), (65000, 65535), (8000, 8100)] {
            // Reserved too, so a port the range misses is denied, not allowed by default.
            let reserved: Vec<u16> = (start..=end).collect();
            let program = loopback_only_program(&[PortRange { start, end }], &reserved)
                .expect("policy encodes");
            for port in start..=end {
                assert_eq!(
                    run(&program, sock_addr::AF_INET, [127, 0, 0, 1], port),
                    ALLOW,
                    "port {port} must be allowed inside {start}-{end}"
                );
            }
        }
    }

    #[test]
    fn bind_ranges_apply_on_the_loopback_and_the_external_path() {
        let ranges = [
            PortRule::tcp(PortRange::single(8000)),
            PortRule::tcp(PortRange { start: 9000, end: 9002 }),
        ];
        let v4 = bind_program(false, &ranges, &[53, 8000, 9000, 9001, 9002]).expect("bind program");
        for port in [8000, 9000, 9001, 9002] {
            assert_eq!(run(&v4, sock_addr::AF_INET, [127, 0, 0, 1], port), ALLOW, "loopback {port}");
            assert_eq!(run(&v4, sock_addr::AF_INET, [0, 0, 0, 0], port), ALLOW, "wildcard {port}");
        }
        for port in [7999, 8001, 8999, 9003] {
            assert_eq!(run(&v4, sock_addr::AF_INET, [0, 0, 0, 0], port), DENY, "wildcard {port}");
        }
    }

    #[test]
    fn reserved_ports_are_derived_not_configured() {
        let parsed = policy(VLLM).unwrap();
        assert_eq!(
            parsed.reserved_ports(),
            BTreeSet::from([53, 8000, 8081]),
            "stub port and declared local service ports only"
        );
        assert_eq!(parsed.reserved_ports_value(), "53,8000,8081");
        let injected = VLLM.replace(
            r#""service_ports": [8000]"#,
            r#""service_ports": [8000], "reserved_ports": [6666]"#,
        );
        assert!(policy(&injected).is_err(), "unknown field is rejected");
    }

    #[test]
    fn missing_container_is_an_error() {
        let parsed = policy(VLLM).unwrap();
        assert!(parsed.container("pause").is_err());
    }

    #[test]
    fn empty_policy_means_unenforced_not_denied() {
        let empty = policy(r#"{"version": 1, "containers": {}}"#).expect("empty document is valid");
        assert!(empty.containers.is_empty());
        assert!(empty.container("vllm").is_err(), "no entry means unenforced");
        assert!(Policy::deny_all().container("vllm").is_err());
        validate(&Policy::deny_all()).expect("explicit deny-all is valid");
    }

    #[test]
    fn rejects_unknown_fields_and_versions() {
        assert!(policy(r#"{"version": 2, "containers": {}}"#).is_err());
        assert!(policy(r#"{"version": 1, "containers": {}, "extra": 1}"#).is_err());
        let unknown_mode = VLLM.replace(r#""mode": "loopback-only""#, r#""mode": "open""#);
        assert!(policy(&unknown_mode).is_err());
    }

    #[test]
    fn service_ports_belong_to_one_container() {
        let doc = |a: &str, b: &str| {
            format!(
                r#"{{"version": 1, "containers": {{
                    "vllm": {{"mode": "loopback-only", "service_ports": [{a}]}},
                    "attestation": {{"mode": "loopback-only", "service_ports": [{b}]}}}}}}"#
            )
        };
        let error = parse(&doc(r#""8000/tcp""#, r#""8000/tcp", "8081/tcp""#))
            .expect_err("two containers serving 8000/tcp could each take the other's listener");
        assert!(format!("{:#}", error).contains("declared by both"), "{:#}", error);
        assert!(parse(&doc(r#""9000-9002""#, r#""9001""#)).is_err(), "overlapping ranges");
        // A container reaches its own loopback ports over either protocol.
        assert!(parse(&doc(r#""8000/tcp""#, r#""8000/udp""#)).is_err(), "8000/tcp and 8000/udp in two containers");
        assert!(parse(&doc(r#""8000""#, r#""8081""#)).is_ok(), "distinct ports");
    }

    /// What genpolicy emits; the pause container carries no container-name annotation.
    const GENPOLICY: &str = r#"package agent_policy

default CreateContainerRequest := false
# policy_data := is referenced here only in a comment
policy_data := {
  "containers": [
    {"OCI": {"Annotations": {"io.kubernetes.cri.container-type": "sandbox"}}},
    {"OCI": {"Annotations": {"io.kubernetes.cri.container-name": "vllm"}}},
    {"OCI": {"Annotations": {"io.kubernetes.cri.container-name": "attestation"}}}
  ],
  "request_defaults": {}
}
"#;

    #[test]
    fn rego_container_names_come_from_policy_data() {
        let names = rego_container_names(GENPOLICY).unwrap().expect("policy_data present");
        assert_eq!(names, BTreeSet::from(["attestation".to_string(), "vllm".to_string()]));
        assert!(rego_container_names("package agent_policy\ndefault CreateContainerRequest := true\n")
            .unwrap()
            .is_none(), "a hand-written policy has no container list");
        assert!(rego_container_names("package p\npolicy_data := {not json").is_err());
        assert!(rego_container_names("package p\npolicy_data := {\"common\": {}}").is_err());
    }

    #[test]
    fn network_policy_must_target_containers_the_agent_policy_creates() {
        let policy = |key: &str| {
            parse(&format!(
                r#"{{"version": 1, "containers": {{"vllm": {{"mode": "loopback-only"}},
                    "{key}": {{"mode": "egress-allowlist", "port_allow": ["443"]}}}}}}"#
            ))
            .unwrap()
        };
        let error = check_targets(&policy("reticle"), Some(GENPOLICY)).expect_err("reticle is not a container");
        assert!(format!("{:#}", error).contains("reticle"), "{:#}", error);
        check_targets(&policy("attestation"), Some(GENPOLICY)).expect("both entries name real containers");
        // Without a genpolicy list the host would choose names freely.
        for rego in [None, Some("package p\ndefault CreateContainerRequest := true\n")] {
            let error = check_targets(&policy("attestation"), rego).expect_err("no genpolicy agent policy");
            assert!(format!("{:#}", error).contains("needs"), "{:#}", error);
        }
        // A policy that names no container needs nothing.
        check_targets(&parse(r#"{"version": 1, "containers": {}}"#).unwrap(), None).expect("empty policy");
        assert!(check_targets(&policy("attestation"), Some("package p\npolicy_data := [")).is_err(),
            "a policy_data that cannot be read fails closed");
    }

    #[test]
    fn prepare_reports_every_boot_failure_as_one_reason() {
        let ok = |_: &str, _: &str| -> Result<()> { Ok(()) };
        let good = parse(r#"{"version": 1, "containers": {"vllm": {"mode": "loopback-only"}}}"#).unwrap();
        prepare(Ok(good.clone()), Some(GENPOLICY), ok).expect("valid policy, real container");
        let error = prepare(Err("unknown field `tcp_allow`".into()), Some(GENPOLICY), ok).unwrap_err();
        assert_eq!(format!("{error:#}"), "unknown field `tcp_allow`");
        let stray = parse(r#"{"version": 1, "containers": {"reticle": {"mode": "loopback-only"}}}"#).unwrap();
        assert!(format!("{:#}", prepare(Ok(stray), Some(GENPOLICY), ok).unwrap_err()).contains("reticle"));
        let failing = |name: &str, _: &str| -> Result<()> { bail!("cannot write {name}") };
        let error = prepare(Ok(good), Some(GENPOLICY), failing).unwrap_err();
        assert!(format!("{:#}", error).contains("kernel.io_uring_disabled"), "{:#}", error);
        let empty = parse(r#"{"version": 1, "containers": {}}"#).unwrap();
        prepare(Ok(empty), None, failing).expect("nothing to harden");
        assert_eq!(refusal("why"), "network-policy.json refused: why");
    }

    #[test]
    fn rejects_two_allowlist_containers() {
        let two = r#"{"version": 1, "containers": {
            "a": {"mode": "egress-allowlist", "dns_allow": ["a.example"],
                  "port_allow": ["443/tcp"]},
            "b": {"mode": "egress-allowlist", "dns_allow": ["b.example"],
                  "port_allow": ["443/tcp"]}
        }}"#;
        let error = policy(two).expect_err("two allowlists are refused");
        assert!(
            error.to_string().contains("at most one container"),
            "{}",
            error
        );
    }

    #[test]
    fn loopback_only_still_rejects_egress_fields() {
        // `VLLM` is the fixture's loopback-only container.
        let bad = VLLM.replace(
            r#""vllm": {"mode": "loopback-only", "service_ports": [8000]}"#,
            r#""vllm": {"mode": "loopback-only", "service_ports": [8000], "dns_allow": ["example.com"]}"#,
        );
        assert_ne!(bad, VLLM, "the fixture must change for this test to mean anything");
        assert!(policy(&bad).is_err(), "loopback-only takes no dns_allow");
    }

    #[test]
    fn egress_allowlist_requires_ports_but_not_dns_names() {
        let no_ports = VLLM.replace(r#""port_allow": ["443/tcp"]"#, r#""port_allow": []"#);
        assert!(policy(&no_ports).is_err(), "an empty port axis allows nothing");
        let cidr_only = r#"{"version": 1, "containers": {
            "attestation": {"mode": "egress-allowlist",
                            "cidr_allow": ["10.0.0.0/8"],
                            "port_allow": ["443/tcp"]}
        }}"#;
        assert!(policy(cidr_only).is_ok(), "cidr_allow alone is a valid axis");
        let no_axis = VLLM.replace(
            r#""dns_allow": ["nras.attestation.nvidia.com"],"#,
            "",
        );
        assert!(
            policy(&no_axis).is_ok(),
            "no destination axis means port_allow alone decides"
        );
    }

    #[test]
    fn validates_container_names_and_dns_names() {
        assert!(valid_container_name("vllm"));
        assert!(valid_container_name("attestation"));
        assert!(!valid_container_name(""));
        assert!(!valid_container_name("-lead"));
        assert!(!valid_container_name("Upper"));
        assert!(!valid_container_name("with_underscore"));
        assert!(valid_dns_name("nras.attestation.nvidia.com"));
        assert!(valid_dns_name("example.com."));
        assert!(!valid_dns_name(""));
        assert!(!valid_dns_name("bad..name"));
        assert!(!valid_dns_name("-lead.example"));
        assert!(!valid_dns_name("wild.*.example"));
    }

    #[test]
    fn dns_block_is_no_longer_part_of_the_policy() {
        let with_dns = VLLM.replace(
            r#""version": 1,"#,
            r#""version": 1, "dns": {"stub": "127.0.0.53:53"},"#,
        );
        let error = parse(&with_dns).expect_err("a dns block must be rejected");
        // anyhow keeps the serde detail in the cause chain, not in the top-level Display.
        let chain = format!("{error:#}");
        assert!(chain.contains("dns"), "unexpected error: {}", chain);
    }

    #[test]
    fn resolv_conf_is_no_longer_part_of_the_policy() {
        let stale = VLLM.replace(
            r#""cidr_allow": []"#,
            r#""cidr_allow": [], "resolv_conf": "/run/podvm/resolv-attestation.conf""#,
        );
        assert!(policy(&stale).is_err());
    }

    #[test]
    fn apply_sysctls_writes_hardening_then_derived_ports() {
        let parsed = policy(VLLM).unwrap();
        let mut written = Vec::new();
        apply_sysctls(&parsed, |name, value| {
            written.push((name.to_string(), value.to_string()));
            Ok(())
        })
        .expect("sysctls apply");
        assert_eq!(
            written,
            vec![
                ("kernel.io_uring_disabled".to_string(), "2".to_string()),
                ("user.max_user_namespaces".to_string(), "0".to_string()),
                ("net.ipv4.tcp_syncookies".to_string(), "0".to_string()),
                (
                    RESERVED_PORTS_SYSCTL.to_string(),
                    "53,8000,8081".to_string()
                ),
            ]
        );
    }

    #[test]
    fn apply_sysctls_fails_closed_on_the_first_error() {
        let parsed = policy(VLLM).unwrap();
        let mut written = Vec::new();
        let error = apply_sysctls(&parsed, |name, value| {
            written.push(name.to_string());
            if name == "user.max_user_namespaces" {
                anyhow::bail!("permission denied");
            }
            let _ = value;
            Ok(())
        })
        .expect_err("a failed sysctl must fail the sandbox");
        assert!(error.to_string().contains("permission denied"));
        // The reserved-port write never happens after a failure.
        assert_eq!(
            written,
            vec!["kernel.io_uring_disabled", "user.max_user_namespaces"]
        );
    }

    #[test]
    fn ports_from_sysctl_parses_a_list() {
        assert_eq!(
            ports_from_sysctl("53,443,8000"),
            BTreeSet::from([53, 443, 8000])
        );
        assert_eq!(ports_from_sysctl(""), BTreeSet::new());
        assert_eq!(ports_from_sysctl(" 53 , 443 "), BTreeSet::from([53, 443]));
        assert_eq!(
            ports_from_sysctl("53,8000,9000-9002"),
            BTreeSet::from([53, 8000, 9000, 9001, 9002])
        );
        assert_eq!(ports_from_sysctl("9000-9002"), BTreeSet::from([9000, 9001, 9002]));
        assert_eq!(ports_from_sysctl("9002-9000"), BTreeSet::new());
        assert_eq!(ports_from_sysctl("9000-"), BTreeSet::new());
    }

    // -----------------------------------------------------------------------------------------
    // Running the compiled programs
    // The embedded programs run in an interpreter that refuses the reads the verifier would.
    // -----------------------------------------------------------------------------------------

    /// `struct bpf_sock_addr` offsets, from the Linux UAPI.
    mod sock_addr {
        pub const USER_FAMILY: usize = 0;
        pub const USER_IP4: usize = 4;
        pub const USER_IP6: usize = 8;
        pub const USER_PORT: usize = 24;
        /// Not 32: that is `type` (SOCK_STREAM/SOCK_DGRAM).
        pub const PROTOCOL: usize = 36;
        /// The whole struct, `sk` pointer included.
        pub const LEN: usize = 72;
        pub const AF_INET: i32 = 2;
    }

    const AF_INET6: i32 = 10;

    /// `struct __sk_buff` offsets, from the Linux UAPI.
    mod sk_buff {
        /// The output device on the egress hook.
        pub const IFINDEX: u64 = 40;
        pub const DATA: u64 = 76;
        pub const DATA_END: u64 = 80;
    }

    struct TestProgram {
        insns: &'static [Insn],
        policy: Vec<u8>,
    }

    fn object() -> &'static Programs {
        programs().expect("the embedded object reads")
    }

    fn with_policy(insns: &'static [Insn], policy: ProgramPolicy) -> Result<TestProgram> {
        Ok(TestProgram { insns, policy: policy.encode()? })
    }

    /// The loopback connect rule ignores the protocol, so TCP stands in for any.
    fn tcp_rules(ranges: &[PortRange]) -> Vec<PortRule> {
        ranges.iter().copied().map(PortRule::tcp).collect()
    }

    fn loopback_policy(service_ports: Vec<PortRule>, reserved: &[u16]) -> ProgramPolicy {
        ProgramPolicy {
            mode: Mode::LoopbackOnly,
            service_ports,
            reserved: reserved.to_vec(),
            port_allow: Vec::new(),
            cidrs: Vec::new(),
            constrained: false,
        }
    }

    fn egress_policy(
        ports: &[PortRule],
        cidrs: &[Cidr],
        constrained: bool,
        service_ports: &[PortRange],
        reserved: &[u16],
    ) -> ProgramPolicy {
        ProgramPolicy {
            mode: Mode::EgressAllowlist,
            service_ports: tcp_rules(service_ports),
            reserved: reserved.to_vec(),
            port_allow: ports.to_vec(),
            cidrs: cidrs.to_vec(),
            constrained,
        }
    }

    fn loopback_only_program(service_ports: &[PortRange], reserved: &[u16]) -> Result<TestProgram> {
        with_policy(&object().outbound4, loopback_policy(tcp_rules(service_ports), reserved))
    }

    fn loopback_only_v6_program(service_ports: &[PortRange], reserved: &[u16]) -> Result<TestProgram> {
        with_policy(&object().outbound6, loopback_policy(tcp_rules(service_ports), reserved))
    }

    fn egress_allowlist_program(
        ports: &[PortRule],
        cidrs: &[Cidr],
        constrained: bool,
        service_ports: &[PortRange],
        reserved: &[u16],
    ) -> Result<TestProgram> {
        with_policy(&object().outbound4, egress_policy(ports, cidrs, constrained, service_ports, reserved))
    }

    fn egress_allowlist_v6_program(
        ports: &[PortRule],
        cidrs: &[Cidr],
        constrained: bool,
        service_ports: &[PortRange],
        reserved: &[u16],
    ) -> Result<TestProgram> {
        with_policy(&object().outbound6, egress_policy(ports, cidrs, constrained, service_ports, reserved))
    }

    /// Binding is judged the same way in both modes.
    fn bind_program(v6: bool, service_ports: &[PortRule], reserved: &[u16]) -> Result<TestProgram> {
        let insns = if v6 { &object().bind6 } else { &object().bind4 };
        with_policy(insns, loopback_policy(service_ports.to_vec(), reserved))
    }

    /// The backstop only reads the mode and the service ports.
    fn egress_backstop_program(service_ports: &[PortRule], loopback_only: bool) -> Result<TestProgram> {
        let mut policy = loopback_policy(service_ports.to_vec(), &[]);
        if !loopback_only {
            policy.mode = Mode::EgressAllowlist;
            policy.port_allow = vec![PortRule::tcp(PortRange::single(443))];
        }
        with_policy(&object().egress, policy)
    }

    fn ip_socket_create_program() -> Result<TestProgram> {
        with_policy(&object().sock_create, loopback_policy(Vec::new(), &[]))
    }

    fn run_proto(prog: &TestProgram, family: i32, ip: [u8; 4], port: u16, protocol: u8) -> i64 {
        let mut ctx = [0u8; sock_addr::LEN];
        ctx[sock_addr::USER_FAMILY..][..4].copy_from_slice(&family.to_le_bytes());
        ctx[sock_addr::USER_IP4..][..4].copy_from_slice(&ip);
        ctx[sock_addr::USER_PORT..][..2].copy_from_slice(&port.to_be_bytes());
        write_protocol(&mut ctx, protocol);
        execute(prog, ctx)
    }

    fn run(prog: &TestProgram, family: i32, ip: [u8; 4], port: u16) -> i64 {
        run_proto(prog, family, ip, port, 6)
    }

    fn run_v6(prog: &TestProgram, ip: [u8; 16], port: u16) -> i64 {
        run_v6_proto(prog, ip, port, 6)
    }

    fn run_v6_proto(prog: &TestProgram, ip: [u8; 16], port: u16, protocol: u8) -> i64 {
        let mut ctx = [0u8; sock_addr::LEN];
        ctx[sock_addr::USER_FAMILY..][..4].copy_from_slice(&AF_INET6.to_le_bytes());
        ctx[sock_addr::USER_IP6..][..16].copy_from_slice(&ip);
        ctx[sock_addr::USER_PORT..][..2].copy_from_slice(&port.to_be_bytes());
        write_protocol(&mut ctx, protocol);
        execute(prog, ctx)
    }

    fn write_protocol(ctx: &mut [u8], protocol: u8) {
        ctx[sock_addr::PROTOCOL..][..4].copy_from_slice(&i32::from(protocol).to_le_bytes());
    }

    fn execute(prog: &TestProgram, ctx: [u8; sock_addr::LEN]) -> i64 {
        execute_with_resolved(prog, ctx, &[])
    }

    /// Run `prog` with `resolved` in the resolved-address map, all unexpired.
    fn execute_with_resolved(prog: &TestProgram, ctx: [u8; sock_addr::LEN], resolved: &[[u8; 16]]) -> i64 {
        let entries: Vec<([u8; 16], u64)> = resolved.iter().map(|key| (*key, u64::MAX)).collect();
        execute_at(prog, ctx, &entries, 0)
    }

    /// Run `prog` with map `entries` of (key, expiry) and `bpf_ktime_get_ns` returning `now`.
    fn execute_at(prog: &TestProgram, ctx: [u8; sock_addr::LEN], entries: &[([u8; 16], u64)], now: u64) -> i64 {
        interpret(prog, &Context::Words(&ctx), entries, now)
    }

    /// What `r1` points at when a program starts.
    enum Context<'a> {
        /// A `bpf_sock_addr` or a `bpf_sock`: plain 32-bit fields.
        Words(&'a [u8]),
        /// A `__sk_buff` for `packet`, leaving through device `ifindex`.
        Packet { packet: &'a [u8], ifindex: u32 },
    }

    // Disjoint address ranges, so a load from the wrong region panics instead of reading zeros.
    const CTX_BASE: u64 = 0x1000_0000;
    const STACK_BASE: u64 = 0x2000_0000;
    const STACK_LEN: u64 = 512;
    /// `r10`: the stack grows down from here.
    const STACK_TOP: u64 = STACK_BASE + STACK_LEN;
    const POLICY_BASE: u64 = 0x3000_0000;
    const PACKET_BASE: u64 = 0x4000_0000;
    /// A lookup hit points at `VALUE_BASE + 8 * index`.
    const VALUE_BASE: u64 = 0x5000_0000;
    /// What a reference to the resolved-address map loads: a handle, never dereferenced.
    const RESOLVED_MAP: u64 = 0x6000_0000;
    /// The longest loop is `MAX_CIDR4` iterations of a few instructions, well under this.
    const STEP_LIMIT: usize = 200_000;

    struct Machine<'a> {
        ctx: &'a Context<'a>,
        policy: &'a [u8],
        entries: &'a [([u8; 16], u64)],
        stack: [u8; STACK_LEN as usize],
        /// Which stack bytes the program has written.
        written: [bool; STACK_LEN as usize],
    }

    impl Machine<'_> {
        fn stack_range(&self, address: u64, len: u64) -> std::ops::Range<usize> {
            assert!(
                address >= STACK_BASE && address + len <= STACK_TOP,
                "access to {address:#x} is outside the stack frame"
            );
            (address - STACK_BASE) as usize..(address - STACK_BASE + len) as usize
        }

        fn load(&self, address: u64, len: u64) -> u64 {
            let mut bytes = [0u8; 8];
            let field = &mut bytes[..len as usize];
            match address {
                CTX_BASE..STACK_BASE => {
                    let offset = address - CTX_BASE;
                    // The verifier refuses a narrower read of most context fields.
                    assert!(len == 4 && offset % 4 == 0, "context field at {offset} read as {len} bytes");
                    match self.ctx {
                        Context::Words(words) => {
                            let at = offset as usize;
                            assert!(at + 4 <= words.len(), "read past the context at {offset}");
                            field.copy_from_slice(&words[at..at + 4]);
                        }
                        Context::Packet { packet, ifindex } => {
                            return match offset {
                                sk_buff::IFINDEX => u64::from(*ifindex),
                                sk_buff::DATA => PACKET_BASE,
                                sk_buff::DATA_END => PACKET_BASE + packet.len() as u64,
                                other => panic!("unexpected __sk_buff offset {other}"),
                            };
                        }
                    }
                }
                STACK_BASE..POLICY_BASE => {
                    let range = self.stack_range(address, len);
                    assert!(self.written[range.clone()].iter().all(|byte| *byte), "read of unwritten stack");
                    field.copy_from_slice(&self.stack[range]);
                }
                POLICY_BASE..PACKET_BASE => {
                    let at = (address - POLICY_BASE) as usize;
                    assert!(at + len as usize <= self.policy.len(), "read past the policy at {at}");
                    field.copy_from_slice(&self.policy[at..at + len as usize]);
                }
                PACKET_BASE..VALUE_BASE => {
                    let Context::Packet { packet, .. } = self.ctx else {
                        panic!("packet read without a packet");
                    };
                    let at = (address - PACKET_BASE) as usize;
                    assert!(at + len as usize <= packet.len(), "packet read out of bounds");
                    field.copy_from_slice(&packet[at..at + len as usize]);
                }
                VALUE_BASE..RESOLVED_MAP => {
                    let offset = address - VALUE_BASE;
                    assert!(len == 8 && offset % 8 == 0, "partial read of a map value");
                    return self.entries[(offset / 8) as usize].1;
                }
                other => panic!("load from {other:#x}, which is not memory"),
            }
            u64::from_le_bytes(bytes)
        }

        fn store(&mut self, address: u64, len: u64, value: u64) {
            let range = self.stack_range(address, len);
            self.stack[range.clone()].copy_from_slice(&value.to_le_bytes()[..len as usize]);
            self.written[range].fill(true);
        }
    }

    fn access_len(code: u8) -> u64 {
        match code & 0x18 {
            0x00 => 4,
            0x08 => 2,
            0x10 => 1,
            _ => 8,
        }
    }

    fn interpret(prog: &TestProgram, ctx: &Context, entries: &[([u8; 16], u64)], now: u64) -> i64 {
        let insns = prog.insns;
        let mut machine = Machine {
            ctx,
            policy: &prog.policy,
            entries,
            stack: [0; STACK_LEN as usize],
            written: [false; STACK_LEN as usize],
        };
        // `None` until written: reading it is the verifier's `!read_ok`.
        let mut regs: [Option<u64>; 11] = [None; 11];
        regs[1] = Some(CTX_BASE);
        regs[10] = Some(STACK_TOP);
        let mut pc = 0usize;
        for _ in 0..STEP_LIMIT {
            let insn = insns[pc];
            let (dst, src) = (usize::from(insn.dst()), usize::from(insn.src()));
            macro_rules! read {
                ($register:expr) => {
                    regs[$register].unwrap_or_else(|| panic!("r{} read before it was written at {}", $register, pc - 1))
                };
            }
            let class = insn.code & 0x07;
            let operation = insn.code & 0xf0;
            pc += 1;
            match class {
                // BPF_ALU (32-bit, zero-extending) and BPF_ALU64.
                0x04 | 0x07 => {
                    let wide = class == 0x07;
                    // BPF_END: a conversion to little- or big-endian of the low `imm` bits.
                    if operation == 0xd0 {
                        assert!(!wide, "unconditional byte swap is not an instruction of this target");
                        let value = read!(dst);
                        let big = insn.code & 0x08 != 0;
                        regs[dst] = Some(match (insn.imm, big) {
                            (16, false) => u64::from(value as u16),
                            (32, false) => u64::from(value as u32),
                            (64, false) => value,
                            (16, true) => u64::from((value as u16).swap_bytes()),
                            (32, true) => u64::from((value as u32).swap_bytes()),
                            (64, true) => value.swap_bytes(),
                            (width, _) => panic!("byte swap of {width} bits"),
                        });
                        continue;
                    }
                    assert_eq!(insn.off, 0, "sign-extending moves and signed division are not modelled");
                    let operand = if insn.code & 0x08 != 0 {
                        read!(src)
                    } else {
                        // An immediate is sign-extended to the width of the operation.
                        i64::from(insn.imm) as u64
                    };
                    let current = if operation == 0xb0 { 0 } else { read!(dst) };
                    let shift = (operand & if wide { 63 } else { 31 }) as u32;
                    let (a, b) = if wide { (current, operand) } else { (u64::from(current as u32), u64::from(operand as u32)) };
                    let result = match operation {
                        0x00 => a.wrapping_add(b),
                        0x10 => a.wrapping_sub(b),
                        0x20 => a.wrapping_mul(b),
                        0x40 => a | b,
                        0x50 => a & b,
                        0x60 => a << shift,
                        0x70 => a >> shift,
                        0x80 => a.wrapping_neg(),
                        0xa0 => a ^ b,
                        0xb0 => b,
                        0xc0 if wide => ((a as i64) >> shift) as u64,
                        0xc0 => ((a as u32 as i32) >> shift) as u32 as u64,
                        other => panic!("unmodelled arithmetic {other:#x} at {}", pc - 1),
                    };
                    regs[dst] = Some(if wide { result } else { u64::from(result as u32) });
                }
                // BPF_LDX: load from memory.
                0x01 => {
                    assert_eq!(insn.code & 0xe0, 0x60, "only plain memory loads are modelled");
                    let address = read!(src).wrapping_add(i64::from(insn.off) as u64);
                    regs[dst] = Some(machine.load(address, access_len(insn.code)));
                }
                // BPF_ST and BPF_STX: store an immediate or a register.
                0x02 | 0x03 => {
                    assert_eq!(insn.code & 0xe0, 0x60, "only plain memory stores are modelled");
                    let address = read!(dst).wrapping_add(i64::from(insn.off) as u64);
                    let value = if class == 0x03 { read!(src) } else { i64::from(insn.imm) as u64 };
                    machine.store(address, access_len(insn.code), value);
                }
                // BPF_LD: only the two-slot 64-bit load, which the reader resolved to a map.
                0x00 => {
                    assert_eq!(insn.code, OP_LD_IMM64);
                    let offset = insns[pc].imm;
                    pc += 1;
                    regs[dst] = Some(match (insn.src() as u8, insn.imm) {
                        (BPF_PSEUDO_MAP_IDX, RESOLVED_MAP_INDEX) => RESOLVED_MAP,
                        (BPF_PSEUDO_MAP_IDX_VALUE, POLICY_MAP_INDEX) => POLICY_BASE + offset as u64,
                        other => panic!("unresolved map reference {other:?}"),
                    });
                }
                // BPF_JMP and BPF_JMP32.
                _ => {
                    let wide = class == 0x05;
                    match (operation, wide) {
                        (0x00, true) => {
                            pc = (pc as i64 + i64::from(insn.off)) as usize;
                            continue;
                        }
                        (0x80, true) => {
                            regs[0] = Some(match insn.imm {
                                BPF_FUNC_MAP_LOOKUP_ELEM => {
                                    assert_eq!(read!(1), RESOLVED_MAP, "lookup in something other than the map");
                                    let range = machine.stack_range(read!(2), 16);
                                    assert!(machine.written[range.clone()].iter().all(|byte| *byte), "lookup key is not fully written");
                                    let key = &machine.stack[range];
                                    entries
                                        .iter()
                                        .position(|(entry, _)| entry == key)
                                        .map_or(0, |index| VALUE_BASE + 8 * index as u64)
                                }
                                BPF_FUNC_KTIME_GET_NS => now,
                                other => panic!("unexpected helper {other}"),
                            });
                            // A helper call clobbers r1-r5, as in the kernel.
                            for clobbered in 1..=5 {
                                regs[clobbered] = None;
                            }
                            continue;
                        }
                        (0x90, true) => {
                            let verdict = read!(0);
                            assert!(verdict <= 1, "verdict {verdict} is neither allow nor deny");
                            return verdict as i64;
                        }
                        _ => {}
                    }
                    let operand = if insn.code & 0x08 != 0 { read!(src) } else { i64::from(insn.imm) as u64 };
                    let (a, b) = if wide { (read!(dst), operand) } else { (u64::from(read!(dst) as u32), u64::from(operand as u32)) };
                    let (signed_a, signed_b) = if wide { (a as i64, b as i64) } else { (i64::from(a as u32 as i32), i64::from(b as u32 as i32)) };
                    let taken = match operation {
                        0x10 => a == b,
                        0x20 => a > b,
                        0x30 => a >= b,
                        0x40 => a & b != 0,
                        0x50 => a != b,
                        0x60 => signed_a > signed_b,
                        0x70 => signed_a >= signed_b,
                        0xa0 => a < b,
                        0xb0 => a <= b,
                        0xc0 => signed_a < signed_b,
                        0xd0 => signed_a <= signed_b,
                        other => panic!("unmodelled jump {other:#x} at {}", pc - 1),
                    };
                    if taken {
                        pc = (pc as i64 + i64::from(insn.off)) as usize;
                    }
                }
            }
        }
        panic!("program did not terminate");
    }

    #[test]
    fn linux_uapi_and_raw_instruction_layout_are_explicit() {
        assert_eq!(BPF_PROG_TYPE_CGROUP_SOCK, 9);
        assert_eq!(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, 18);
        assert_eq!(BPF_CGROUP_INET_SOCK_CREATE, 2);
        assert_eq!(BPF_CGROUP_INET4_BIND, 8);
        assert_eq!(BPF_CGROUP_INET6_BIND, 9);
        assert_eq!(BPF_CGROUP_INET4_CONNECT, 10);
        assert_eq!(BPF_CGROUP_INET6_CONNECT, 11);
        assert_eq!(BPF_CGROUP_UDP4_SENDMSG, 14);
        assert_eq!(BPF_CGROUP_UDP6_SENDMSG, 15);
        // `r3 = *(u32 *)(r6 + 4)`, in the kernel's `struct bpf_insn` layout.
        let insn = Insn { code: 0x61, regs: 0x63, off: 4, imm: 0 };
        let bytes = unsafe {
            std::slice::from_raw_parts(&insn as *const Insn as *const u8, std::mem::size_of::<Insn>())
        };
        assert_eq!(bytes, &[0x61, 0x63, 0x04, 0, 0, 0, 0, 0]);
        assert_eq!((insn.dst(), insn.src()), (3, 6));
    }

    /// Derived from the UAPI field order rather than restated as literals.
    #[test]
    fn sock_addr_offsets_match_the_uapi_struct() {
        // (name, words) in declaration order, from the UAPI header.
        let fields: [(&str, usize); 8] = [
            ("user_family", 1),
            ("user_ip4", 1),
            ("user_ip6", 4),
            ("user_port", 1),
            ("family", 1),
            ("type", 1),
            ("protocol", 1),
            ("msg_src_ip4", 1),
        ];
        let mut offset: usize = 0;
        let mut offsets = std::collections::BTreeMap::new();
        for (name, words) in fields {
            offsets.insert(name, offset);
            offset += words * 4;
        }
        assert_eq!(offsets["user_family"], sock_addr::USER_FAMILY);
        assert_eq!(offsets["user_ip4"], sock_addr::USER_IP4);
        assert_eq!(offsets["user_port"], sock_addr::USER_PORT);
        assert_eq!(offsets["protocol"], sock_addr::PROTOCOL);
        // Spelled out so the intent survives a careless edit to the table above.
        assert_eq!(offsets["type"], 32);
        assert_eq!(sock_addr::PROTOCOL, 36);
        assert_ne!(sock_addr::PROTOCOL, offsets["type"], "protocol is not type");
        assert_eq!(sock_addr::AF_INET, 2);
    }

    #[test]
    fn embedded_object_holds_the_programs_enforce_attaches() {
        let programs = object();
        assert_eq!(programs.license.to_bytes(), b"GPL");
        for (name, insns) in [
            ("sock_create", &programs.sock_create),
            ("outbound4", &programs.outbound4),
            ("outbound6", &programs.outbound6),
            ("bind4", &programs.bind4),
            ("bind6", &programs.bind6),
            ("egress", &programs.egress),
        ] {
            assert!(!insns.is_empty(), "{name} is empty");
            // The kernel refuses a program longer than this without CAP_BPF-only limits.
            assert!(insns.len() <= 4096, "{name} has {} instructions", insns.len());
        }
        // The socket-creation program consults no policy and no map.
        assert!(programs.sock_create.iter().all(|insn| insn.code != OP_LD_IMM64));
    }

    /// Byte offset of the contents of the first section of `kind` in the embedded object.
    fn section_offset(kind: u32) -> usize {
        let table = le_usize(OBJECT, 40).unwrap();
        (0..usize::from(le_u16(OBJECT, 60).unwrap()))
            .map(|index| &OBJECT[table + index * ELF_SECTION_LEN..][..ELF_SECTION_LEN])
            .find(|header| le_u32(header, 4).unwrap() == kind)
            .map(|header| le_usize(header, 24).unwrap())
            .expect("the object has such a section")
    }

    fn position(haystack: &[u8], needle: &[u8]) -> usize {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("the object contains the bytes")
    }

    #[test]
    fn object_reader_refuses_what_it_was_not_written_for() {
        let refused = |edit: &dyn Fn(&mut Vec<u8>), expected: &str| {
            let mut bytes = OBJECT.to_vec();
            edit(&mut bytes);
            let error = format!("{:#}", read_object(&bytes).expect_err(expected));
            assert!(error.contains(expected), "expected {expected:?}, got {error:?}");
        };
        refused(&|bytes| bytes.truncate(40), "not an ELF object");
        refused(&|bytes| bytes[0] = 0, "not an ELF object");
        // EM_X86_64 instead of EM_BPF.
        refused(&|bytes| bytes[18] = 62, "not a relocatable eBPF object");
        refused(&|bytes| bytes.truncate(bytes.len() - 1), "truncated section table");
        // A section the reader does not know.
        refused(
            &|bytes| {
                let at = position(bytes, b".rodata\0");
                bytes[at + 1] = b'x';
            },
            "unexpected section",
        );
        // A program under another name: the expected one is missing.
        refused(
            &|bytes| {
                let at = position(bytes, b"netpol/egress\0");
                bytes[at + 7] = b'x';
            },
            "the object has no egress program",
        );
        // A resolved-address map of another shape than the one `create_resolved_map` makes.
        refused(
            &|bytes| {
                let definition: Vec<u8> = [BPF_MAP_TYPE_LRU_HASH, RESOLVED_KEY_LEN, RESOLVED_VALUE_LEN]
                    .iter()
                    .flat_map(|field| field.to_le_bytes())
                    .collect();
                let at = position(bytes, &definition);
                bytes[at + 4] = 32;
            },
            "not the one this agent creates",
        );
        // A relocation of a kind the reader does not apply.
        refused(
            &|bytes| {
                let at = section_offset(SHT_REL);
                bytes[at + 8] = 10;
            },
            "unsupported relocation type",
        );
        // A relocation that does not sit on a 64-bit load.
        refused(
            &|bytes| {
                let at = section_offset(SHT_REL);
                bytes[at] = bytes[at].wrapping_add(8);
            },
            "is not on a 64-bit load",
        );
    }

    #[test]
    fn map_references_are_positions_not_descriptors() {
        let programs = object();
        for insns in [&programs.outbound4, &programs.outbound6, &programs.bind4, &programs.bind6, &programs.egress] {
            let mut policy_reads = 0;
            let mut index = 0;
            while index < insns.len() {
                let insn = insns[index];
                if insn.code == OP_LD_IMM64 {
                    match insn.src() {
                        BPF_PSEUDO_MAP_IDX => assert_eq!(insn.imm, RESOLVED_MAP_INDEX),
                        BPF_PSEUDO_MAP_IDX_VALUE => {
                            assert_eq!(insn.imm, POLICY_MAP_INDEX);
                            assert!((insns[index + 1].imm as usize) < layout::LEN);
                            policy_reads += 1;
                        }
                        other => panic!("unresolved reference kind {other}"),
                    }
                    index += 1;
                }
                index += 1;
            }
            assert!(policy_reads > 0, "every policy-bound program reads its policy");
        }
    }

    #[test]
    fn policy_is_encoded_where_the_programs_read_it() {
        let policy = ProgramPolicy {
            mode: Mode::EgressAllowlist,
            service_ports: vec![
                PortRule::tcp(PortRange::single(8000)),
                PortRule { range: PortRange { start: 9000, end: 9002 }, protocol: Protocol::Udp },
            ],
            reserved: vec![53, 8081, 65535],
            port_allow: vec![
                PortRule::tcp(PortRange::single(443)),
                PortRule { range: PortRange::single(0), protocol: Protocol::Udp },
            ],
            cidrs: vec![
                parse_cidr("10.160.0.0/12").unwrap(),
                parse_cidr("2001:db8::/33").unwrap(),
                parse_cidr("192.0.2.1/32").unwrap(),
            ],
            constrained: true,
        };
        let bytes = policy.encode().unwrap();
        assert_eq!(bytes.len(), layout::LEN);
        let word = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let ports = |set: usize| -> Vec<u16> {
            (0..=u16::MAX)
                .filter(|port| bytes[set + usize::from(port >> 3)] & (1 << (port & 7)) != 0)
                .collect()
        };
        assert_eq!(word(layout::MODE), MODE_EGRESS_ALLOWLIST);
        assert_eq!(word(layout::CONSTRAINED), 1);
        assert_eq!((word(layout::ANY_V4), word(layout::ANY_V6)), (0, 0));
        assert_eq!((word(layout::CIDR4_COUNT), word(layout::CIDR6_COUNT)), (2, 1));
        assert_eq!(ports(layout::OWN_TCP), [8000]);
        assert_eq!(ports(layout::OWN_UDP), [9000, 9001, 9002]);
        assert_eq!(ports(layout::RESERVED), [53, 8081, 65535]);
        assert_eq!(ports(layout::ALLOW_TCP), [443]);
        assert_eq!(ports(layout::ALLOW_UDP), [0]);
        assert_eq!(bytes[layout::CIDR4..][..8], [0xff, 0xf0, 0, 0, 10, 160, 0, 0]);
        assert_eq!(bytes[layout::CIDR4 + 8..][..8], [0xff, 0xff, 0xff, 0xff, 192, 0, 2, 1]);
        assert_eq!(bytes[layout::CIDR6..][..8], [0xff, 0xff, 0xff, 0xff, 0x80, 0, 0, 0]);
        assert_eq!(bytes[layout::CIDR6 + 16..][..8], [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0]);

        let loopback = loopback_policy(Vec::new(), &[]).encode().unwrap();
        assert_eq!(u32::from_le_bytes(loopback[..4].try_into().unwrap()), MODE_LOOPBACK_ONLY);
        let any = egress_policy(
            &[PortRule::tcp(PortRange::single(443))],
            &[parse_cidr("0.0.0.0/0").unwrap(), parse_cidr("::/0").unwrap()],
            true,
            &[],
            &[],
        )
        .encode()
        .unwrap();
        assert_eq!(any[layout::ANY_V4..][..8], [1, 0, 0, 0, 1, 0, 0, 0]);
    }

    /// The object ships an all-zero `policy`, which must deny.
    #[test]
    fn an_unset_or_unknown_policy_denies_everything() {
        let programs = object();
        let mut unknown = loopback_policy(vec![PortRule::tcp(PortRange::single(8000))], &[]).encode().unwrap();
        unknown[layout::MODE] = 3;
        for policy in [vec![0u8; layout::LEN], unknown] {
            let with = |insns: &'static [Insn]| TestProgram { insns, policy: policy.clone() };
            assert_eq!(run(&with(&programs.outbound4), sock_addr::AF_INET, [127, 0, 0, 1], 8000), DENY);
            assert_eq!(run(&with(&programs.bind4), sock_addr::AF_INET, [127, 0, 0, 1], 8000), DENY);
            let mut loopback = [0u8; 16];
            loopback[15] = 1;
            assert_eq!(run_v6(&with(&programs.outbound6), loopback, 8000), DENY);
            assert_eq!(run_v6(&with(&programs.bind6), loopback, 8000), DENY);
            assert_eq!(run_skb(&with(&programs.egress), &tcp4([127, 0, 0, 1], 40000, ACK)), DENY);
        }
    }

    #[test]
    fn prefix_lists_are_matched_to_the_end_and_bounded() {
        let ports = [PortRule::tcp(PortRange::single(443))];
        let v4: Vec<Cidr> = (0..MAX_CIDR4)
            .map(|index| parse_cidr(&format!("10.{}.{}.0/24", index / 256, index % 256)).unwrap())
            .collect();
        let program = egress_allowlist_program(&ports, &v4, true, &[], &[]).expect("the longest IPv4 list");
        assert_eq!(run(&program, sock_addr::AF_INET, [10, 0, 0, 9], 443), ALLOW, "first prefix");
        assert_eq!(run(&program, sock_addr::AF_INET, [10, 0, 255, 9], 443), ALLOW, "last prefix");
        assert_eq!(run(&program, sock_addr::AF_INET, [10, 1, 0, 9], 443), DENY, "past the last prefix");

        let v6: Vec<Cidr> = (0..MAX_CIDR6)
            .map(|index| parse_cidr(&format!("2001:db8:{index:x}::/48")).unwrap())
            .collect();
        let program = egress_allowlist_v6_program(&ports, &v6, true, &[], &[]).expect("the longest IPv6 list");
        let address = |text: &str| text.parse::<std::net::Ipv6Addr>().unwrap().octets();
        assert_eq!(run_v6(&program, address("2001:db8:0::9"), 443), ALLOW, "first prefix");
        assert_eq!(run_v6(&program, address("2001:db8:ff::9"), 443), ALLOW, "last prefix");
        assert_eq!(run_v6(&program, address("2001:db8:100::9"), 443), DENY, "past the last prefix");

        let mut too_many = v4.clone();
        too_many.push(parse_cidr("192.0.2.0/24").unwrap());
        let error = egress_allowlist_program(&ports, &too_many, true, &[], &[]).err().expect("one prefix too many");
        assert!(format!("{error:#}").contains("at most"), "{error:#}");
        let mut too_many = v6.clone();
        too_many.push(parse_cidr("2001:db9::/32").unwrap());
        assert!(egress_allowlist_v6_program(&ports, &too_many, true, &[], &[]).is_err());
    }

    #[test]
    fn listener_check_reads_the_header_up_to_the_flags_and_no_further() {
        let services = [PortRule::tcp(PortRange::single(8000))];
        let program = egress_backstop_program(&services, false).expect("backstop");
        let external4 = [203, 0, 113, 7];
        let external6: [u8; 16] = "2001:db8::7".parse::<std::net::Ipv6Addr>().unwrap().octets();
        for (flags_end, own, other) in [
            (34, tcp4(external4, 8000, SYN_ACK), tcp4(external4, 40000, SYN_ACK)),
            (54, tcp6(external6, 8000, SYN_ACK), tcp6(external6, 40000, SYN_ACK)),
        ] {
            assert_eq!(run_skb_on(&program, &own[..flags_end], 2), ALLOW, "declared listener");
            assert_eq!(run_skb_on(&program, &other[..flags_end], 2), DENY, "undeclared listener");
            assert_eq!(run_skb_on(&program, &own[..flags_end - 1], 2), DENY, "flags cut off");
        }
    }

    #[test]
    fn generated_cidr_rules_match_the_model_at_every_boundary() {
        let cases = [
            ("128.0.0.0/1", [192, 0, 2, 1], [126, 255, 255, 254]),
            ("10.0.0.0/8", [10, 200, 3, 4], [11, 0, 0, 1]),
            ("10.160.0.0/12", [10, 175, 255, 254], [10, 176, 0, 0]),
            ("34.120.0.0/16", [34, 120, 45, 54], [34, 121, 45, 54]),
            ("192.168.1.0/24", [192, 168, 1, 200], [192, 168, 2, 1]),
            ("192.168.1.0/25", [192, 168, 1, 127], [192, 168, 1, 128]),
            ("192.168.1.2/31", [192, 168, 1, 3], [192, 168, 1, 4]),
            ("192.168.1.1/32", [192, 168, 1, 1], [192, 168, 1, 2]),
        ];
        for (prefix, inside, outside) in cases {
            let cidrs = [parse_cidr(prefix).expect("test CIDR")];
            let program = egress_allowlist_program(&[PortRule::tcp(PortRange::single(443))], &cidrs, true, &[], &[]).expect("policy encodes");
            assert_eq!(run(&program, 2, inside, 443), ALLOW, "{prefix} inside");
            assert_eq!(run(&program, 2, outside, 443), DENY, "{prefix} outside");
        }
        let zero = [parse_cidr("0.0.0.0/0").expect("zero prefix")];
        let any_zero = egress_allowlist_program(&[PortRule::tcp(PortRange::single(443))], &zero, true, &[], &[]).expect("policy encodes");
        assert_eq!(run(&any_zero, 2, [1, 2, 3, 4], 443), ALLOW);
        let any = egress_allowlist_program(&[PortRule::tcp(PortRange::single(443))], &[], false, &[], &[]).expect("policy encodes");
        assert_eq!(run(&any, 2, [200, 1, 2, 3], 443), ALLOW);
    }

    #[test]
    fn resolved_entries_admit_only_until_they_expire() {
        let ports = [PortRule::tcp(PortRange::single(443))];
        let v4_program = egress_allowlist_program(&ports, &[], true, &[], &[]).expect("policy encodes");
        let v6_program = egress_allowlist_v6_program(&ports, &[], true, &[], &[]).expect("policy encodes");
        let v4 = resolved_key(IpAddr::from([203, 0, 113, 7]));
        let mut v4_ctx = [0u8; sock_addr::LEN];
        v4_ctx[0..4].copy_from_slice(&2i32.to_le_bytes());
        v4_ctx[4..8].copy_from_slice(&[203, 0, 113, 7]);
        v4_ctx[24..26].copy_from_slice(&443u16.to_be_bytes());
        write_protocol(&mut v4_ctx, 6);
        let v6: [u8; 16] = "2001:db8::7".parse::<std::net::Ipv6Addr>().unwrap().octets();
        let mut v6_ctx = [0u8; sock_addr::LEN];
        v6_ctx[0..4].copy_from_slice(&10i32.to_le_bytes());
        v6_ctx[8..24].copy_from_slice(&v6);
        v6_ctx[24..26].copy_from_slice(&443u16.to_be_bytes());
        write_protocol(&mut v6_ctx, 6);
        for (program, ctx, key) in [(&v4_program, v4_ctx, v4), (&v6_program, v6_ctx, v6)] {
            assert_eq!(execute_at(program, ctx, &[(key, 1_000)], 999), ALLOW, "before expiry");
            assert_eq!(execute_at(program, ctx, &[(key, 1_000)], 1_000), DENY, "at expiry");
            assert_eq!(execute_at(program, ctx, &[(key, 1_000)], 5_000), DENY, "after expiry");
        }
    }

    #[test]
    fn resolved_addresses_are_admitted_and_nothing_else() {
        let ports = [PortRule::tcp(PortRange::single(443))];
        // dns_allow-only: destination axis exists, no configured CIDRs.
        let program = egress_allowlist_program(&ports, &[], true, &[], &[]).expect("policy encodes");
        let resolved = [resolved_key(IpAddr::from([203, 0, 113, 7]))];
        let ctx = |ip: [u8; 4], port: u16, protocol: u8| {
            let mut c = [0u8; sock_addr::LEN];
            c[0..4].copy_from_slice(&2i32.to_le_bytes());
            c[4..8].copy_from_slice(&ip);
            c[24..26].copy_from_slice(&port.to_be_bytes());
            write_protocol(&mut c, protocol);
            c
        };
        assert_eq!(
            execute_with_resolved(&program, ctx([203, 0, 113, 7], 443, 6), &resolved),
            ALLOW,
            "the resolved address must be reachable"
        );
        assert_eq!(
            execute_with_resolved(&program, ctx([203, 0, 113, 8], 443, 6), &resolved),
            DENY,
            "an address the resolver never returned must stay denied"
        );
        assert_eq!(
            execute_with_resolved(&program, ctx([203, 0, 113, 7], 80, 6), &resolved),
            DENY,
            "the resolved address is still limited to allowed ports"
        );
        // Same address, but the filter has published nothing yet.
        assert_eq!(
            execute_with_resolved(&program, ctx([203, 0, 113, 7], 443, 6), &[]),
            DENY,
            "an empty map admits nothing"
        );
    }

    #[test]
    fn resolved_ipv6_addresses_are_looked_up_by_the_full_address() {
        let ports = [PortRule::tcp(PortRange::single(443))];
        let program = egress_allowlist_v6_program(&ports, &[], true, &[], &[]).expect("policy encodes");
        let nras: std::net::Ipv6Addr = "2600:1900:4000::1".parse().unwrap();
        let resolved = [resolved_key(IpAddr::V6(nras))];
        let ctx = |ip: [u8; 16]| {
            let mut c = [0u8; sock_addr::LEN];
            c[0..4].copy_from_slice(&AF_INET6.to_le_bytes());
            c[8..24].copy_from_slice(&ip);
            c[24..26].copy_from_slice(&443u16.to_be_bytes());
            write_protocol(&mut c, 6);
            c
        };
        assert_eq!(execute_with_resolved(&program, ctx(nras.octets()), &resolved), ALLOW);
        // Differs only in the last word: the whole address is the key, not a prefix of it.
        let mut neighbour = nras.octets();
        neighbour[15] = 2;
        assert_eq!(execute_with_resolved(&program, ctx(neighbour), &resolved), DENY);
    }

    /// `::/0` must not admit all of IPv4, and an allowed IPv4 prefix admits dual-stack clients.
    #[test]
    fn mapped_destinations_follow_the_ipv4_rules() {
        let ports = [PortRule::tcp(PortRange::single(443))];
        let mapped = |ip: [u8; 4]| std::net::Ipv4Addr::from(ip).to_ipv6_mapped().octets();
        let ipv6: [u8; 16] = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().octets();

        let ten = egress_allowlist_v6_program(&ports, &[parse_cidr("10.0.0.0/8").unwrap()], true, &[], &[]).unwrap();
        assert_eq!(run_v6(&ten, mapped([10, 1, 2, 3]), 443), ALLOW, "inside the IPv4 prefix");
        assert_eq!(run_v6(&ten, mapped([11, 1, 2, 3]), 443), DENY, "outside it");
        assert_eq!(run_v6(&ten, mapped([10, 1, 2, 3]), 80), DENY, "a port not allowed");
        assert_eq!(run_v6(&ten, ipv6, 443), DENY, "no IPv6 prefix");

        let any4 = egress_allowlist_v6_program(&ports, &[parse_cidr("0.0.0.0/0").unwrap()], true, &[], &[]).unwrap();
        assert_eq!(run_v6(&any4, mapped([203, 0, 113, 9]), 443), ALLOW, "0.0.0.0/0 covers IPv4");
        assert_eq!(run_v6(&any4, ipv6, 443), DENY, "but not IPv6");

        let any6 = egress_allowlist_v6_program(&ports, &[parse_cidr("::/0").unwrap()], true, &[], &[]).unwrap();
        assert_eq!(run_v6(&any6, ipv6, 443), ALLOW, "::/0 covers IPv6");
        assert_eq!(run_v6(&any6, mapped([203, 0, 113, 9]), 443), DENY, "but not IPv4");

        // A dns_allow-only policy: the resolver publishes IPv4 under the same mapped key.
        let names = egress_allowlist_v6_program(&ports, &[], true, &[], &[]).unwrap();
        let resolved = [resolved_key(IpAddr::V4([203, 0, 113, 7].into()))];
        let ctx = |ip: [u8; 16]| {
            let mut c = [0u8; sock_addr::LEN];
            c[sock_addr::USER_FAMILY..][..4].copy_from_slice(&AF_INET6.to_le_bytes());
            c[sock_addr::USER_IP6..][..16].copy_from_slice(&ip);
            c[sock_addr::USER_PORT..][..2].copy_from_slice(&443u16.to_be_bytes());
            write_protocol(&mut c, 6);
            c
        };
        assert_eq!(execute_with_resolved(&names, ctx(mapped([203, 0, 113, 7])), &resolved), ALLOW);
        assert_eq!(execute_with_resolved(&names, ctx(mapped([203, 0, 113, 8])), &resolved), DENY);
    }

    #[test]
    fn resolved_keys_do_not_alias_across_families() {
        // An IPv4 key zero-extended to 16 bytes would equal the IPv6 address a0b:c0d::.
        let v4 = resolved_key(IpAddr::from([10, 11, 12, 13]));
        let v6 = resolved_key("a0b:c0d::".parse().unwrap());
        assert_ne!(v4, v6);
        assert_eq!(v4, "::ffff:10.11.12.13".parse::<std::net::Ipv6Addr>().unwrap().octets());
        let ports = [PortRule::tcp(PortRange::single(443))];
        let v6_program = egress_allowlist_v6_program(&ports, &[], true, &[], &[]).expect("policy encodes");
        let mut c = [0u8; sock_addr::LEN];
        c[0..4].copy_from_slice(&AF_INET6.to_le_bytes());
        c[8..24].copy_from_slice(&v6);
        c[24..26].copy_from_slice(&443u16.to_be_bytes());
        write_protocol(&mut c, 6);
        assert_eq!(execute_with_resolved(&v6_program, c, &[v4]), DENY);
    }

    /// The device the kernel picks: `lo` (1) for a local destination, the wire (2) otherwise.
    fn natural_ifindex(packet: &[u8]) -> u32 {
        let local = match packet.first().map(|byte| byte >> 4) {
            Some(4) if packet.len() >= 20 => packet[16] == 127 || packet[16..20] == [0, 0, 0, 0],
            Some(6) if packet.len() >= 40 => packet[24..39].iter().all(|byte| *byte == 0) && packet[39] <= 1,
            _ => true,
        };
        if local { 1 } else { 2 }
    }

    /// Run the backstop with the packet leaving on its natural device.
    fn run_skb(prog: &TestProgram, packet: &[u8]) -> i64 {
        run_skb_on(prog, packet, natural_ifindex(packet))
    }

    fn run_skb_on(prog: &TestProgram, packet: &[u8], ifindex: u32) -> i64 {
        interpret(prog, &Context::Packet { packet, ifindex }, &[], 0)
    }

    fn tcp4(dst: [u8; 4], source_port: u16, flags: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[33] = flags;
        packet
    }

    fn tcp6(dst: [u8; 16], source_port: u16, flags: u8) -> Vec<u8> {
        let mut packet = vec![0u8; 60];
        packet[0] = 0x60;
        packet[6] = 6;
        packet[24..40].copy_from_slice(&dst);
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[53] = flags;
        packet
    }

    const SYN: u8 = 0x02;
    const ACK: u8 = 0x10;
    const SYN_ACK: u8 = 0x12;

    #[test]
    fn egress_backstop_drops_ip_options_and_ipv6_extension_headers() {
        let program = egress_backstop_program(&[], false).expect("policy encodes");
        let ipv4 = |ihl: u8| {
            let mut p = vec![0u8; usize::from(ihl) * 4];
            p[0] = 0x40 | ihl;
            p
        };
        let ipv6 = |next: u8| {
            let mut p = vec![0u8; 40];
            p[0] = 0x60;
            p[6] = next;
            p
        };
        assert_eq!(run_skb(&program, &ipv4(5)), ALLOW, "plain IPv4");
        assert_eq!(run_skb(&program, &ipv4(6)), DENY, "IPv4 with 4 bytes of options");
        // A loose source route via 203.0.113.7.
        let mut lsrr = ipv4(7);
        lsrr[20..28].copy_from_slice(&[0x83, 7, 4, 203, 0, 113, 7, 0]);
        assert_eq!(run_skb(&program, &lsrr), DENY, "IPv4 loose source route");
        assert_eq!(run_skb(&program, &ipv4(15)), DENY, "maximum IHL");
        for next in [17u8, 44] {
            assert_eq!(run_skb(&program, &ipv6(next)), ALLOW, "IPv6 next header {}", next);
        }
        assert_eq!(run_skb(&program, &tcp6([0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 443, ACK)),
                   ALLOW, "IPv6 TCP");
        for next in [0u8, 43, 60, 58, 50, 59] {
            assert_eq!(run_skb(&program, &ipv6(next)), DENY, "IPv6 next header {}", next);
        }
        assert_eq!(run_skb(&program, &[]), DENY, "empty packet");
        assert_eq!(run_skb(&program, &ipv6(17)[..39]), DENY, "truncated IPv6 header");
        assert_eq!(run_skb(&program, &[0x55]), DENY, "IP version 5");
    }

    #[test]
    fn egress_backstop_answers_handshakes_only_from_declared_listeners() {
        let services = [PortRule::tcp(PortRange::single(8000)), PortRule::tcp(PortRange { start: 9000, end: 9002 })];
        let program = egress_backstop_program(&services, false).expect("policy encodes");
        let outside = [10, 244, 0, 1];
        let outside6 = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut loopback6 = [0u8; 16];
        loopback6[15] = 1;
        assert_eq!(run_skb(&program, &tcp4(outside, 42853, SYN_ACK)), DENY, "undeclared listener");
        assert_eq!(run_skb(&program, &tcp4(outside, 8000, SYN_ACK)), ALLOW, "declared service");
        assert_eq!(run_skb(&program, &tcp4(outside, 9001, SYN_ACK)), ALLOW, "inside a range");
        assert_eq!(run_skb(&program, &tcp4(outside, 9003, SYN_ACK)), DENY, "past a range");
        assert_eq!(run_skb(&program, &tcp4([127, 0, 0, 1], 42853, SYN_ACK)), ALLOW, "loopback handshake");
        assert_eq!(run_skb(&program, &tcp4([127, 0, 0, 2], 42853, SYN_ACK)), ALLOW, "127/8");
        // The container's own outbound connections and their traffic are the connect hook's job.
        assert_eq!(run_skb(&program, &tcp4(outside, 42853, SYN)), ALLOW, "outbound SYN");
        assert_eq!(run_skb(&program, &tcp4(outside, 42853, ACK)), ALLOW, "established traffic");
        let mut udp = tcp4(outside, 42853, 0);
        udp[9] = 17;
        assert_eq!(run_skb(&program, &udp), ALLOW, "UDP");
        assert_eq!(run_skb(&program, &tcp4(outside, 42853, SYN_ACK)[..30]), DENY, "truncated TCP header");
        assert_eq!(run_skb(&program, &tcp6(outside6, 42853, SYN_ACK)), DENY, "IPv6 undeclared");
        assert_eq!(run_skb(&program, &tcp6(outside6, 8000, SYN_ACK)), ALLOW, "IPv6 declared");
        assert_eq!(run_skb(&program, &tcp6(loopback6, 42853, SYN_ACK)), ALLOW, "IPv6 loopback");
        assert_eq!(run_skb(&program, &tcp6(outside6, 42853, SYN)), ALLOW, "IPv6 outbound SYN");
        let closed = egress_backstop_program(&[], false).expect("policy encodes");
        assert_eq!(run_skb(&closed, &tcp4(outside, 8000, SYN_ACK)), DENY);
    }

    /// `IP_PKTINFO`, `IP_UNICAST_IF` and `SO_BINDTODEVICE` can send local traffic out the wire.
    #[test]
    fn egress_backstop_keeps_local_destinations_on_loopback() {
        let services = [PortRule::tcp(PortRange::single(8000))];
        for loopback_only in [false, true] {
            let program = egress_backstop_program(&services, loopback_only).expect("policy encodes");
            let udp4 = |dst: [u8; 4]| {
                let mut packet = tcp4(dst, 8000, 0);
                packet[9] = 17;
                packet
            };
            let udp6 = |dst: [u8; 16]| {
                let mut packet = tcp6(dst, 8000, 0);
                packet[6] = 17;
                packet
            };
            let v6 = |text: &str| text.parse::<std::net::Ipv6Addr>().unwrap().octets();
            for dst in [[127, 0, 0, 1], [127, 0, 0, 2], [0, 0, 0, 0]] {
                assert_eq!(run_skb_on(&program, &udp4(dst), 1), ALLOW, "{:?} on lo", dst);
                assert_eq!(run_skb_on(&program, &udp4(dst), 2), DENY, "{:?} forced off lo", dst);
                assert_eq!(run_skb_on(&program, &tcp4(dst, 8000, SYN), 2), DENY, "{:?} TCP forced off lo", dst);
            }
            for dst in ["::1", "::", "::ffff:127.0.0.2"] {
                assert_eq!(run_skb_on(&program, &udp6(v6(dst)), 2), DENY, "{} forced off lo", dst);
            }
            assert_eq!(run_skb_on(&program, &udp6(v6("::1")), 1), ALLOW, "::1 on lo");
        }
    }

    /// This also stops SYN-cookie handshakes on undeclared listeners, whose SYN-ACKs no hook sees.
    #[test]
    fn loopback_only_backstop_lets_only_own_listeners_off_loopback() {
        let services = [PortRule::tcp(PortRange::single(8000)), PortRule { range: PortRange::single(5353), protocol: Protocol::Udp }];
        let local = egress_backstop_program(&services, true).expect("policy encodes");
        let egress = egress_backstop_program(&services, false).expect("policy encodes");
        let client = [10, 244, 0, 1];
        let client6 = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let with = |mut packet: Vec<u8>, at: usize, byte: u8| {
            packet[at] = byte;
            packet
        };
        let cases = [
            (tcp4(client, 8000, ACK), ALLOW, "TCP reply from the TCP service"),
            (tcp4(client, 8000, SYN_ACK), ALLOW, "handshake of the TCP service"),
            (tcp4(client, 42853, ACK), DENY, "TCP from an undeclared port"),
            (with(tcp4(client, 5353, 0), 9, 17), ALLOW, "UDP reply from the UDP service"),
            (with(tcp4(client, 8000, 0), 9, 17), DENY, "UDP from the TCP service port"),
            (tcp4(client, 5353, ACK), DENY, "TCP from the UDP service port"),
            (with(tcp4(client, 8000, ACK), 6, 0x20), DENY, "IPv4 fragment"),
            (with(tcp4(client, 8000, ACK), 9, 1), DENY, "ICMP"),
            (tcp6(client6, 8000, ACK), ALLOW, "IPv6 TCP reply from the service"),
            (tcp6(client6, 42853, ACK), DENY, "IPv6 TCP from an undeclared port"),
            (with(tcp6(client6, 5353, 0), 6, 17), ALLOW, "IPv6 UDP reply from the service"),
            (with(tcp6(client6, 8000, ACK), 6, 44), DENY, "IPv6 fragment"),
        ];
        for (packet, want, case) in cases {
            assert_eq!(run_skb_on(&local, &packet, 2), want, "loopback-only: {}", case);
        }
        // An egress-allowlist container's own connections leave from ephemeral ports.
        assert_eq!(run_skb_on(&egress, &tcp4(client, 42853, ACK), 2), ALLOW, "egress-allowlist");
        // On lo nothing changes: NCCL, Gloo and ZMQ use ephemeral loopback ports.
        assert_eq!(run_skb_on(&local, &tcp4([127, 0, 0, 1], 42853, ACK), 1), ALLOW, "loopback traffic");
    }

    #[test]
    #[ignore = "requires root, CAP_BPF and a writable cgroup2 hierarchy"]
    fn kernel_enforcement_drops_source_routed_packets() {
        let dir = PathBuf::from(format!("/sys/fs/cgroup/netpol-test-{}", std::process::id()));
        std::fs::create_dir(&dir).expect("create a scratch cgroup");
        // "s" is a sibling only so that its service port, 8081, is reserved.
        let policy = parse(
            r#"{"version": 1, "containers": {
                "c": {"mode": "loopback-only", "service_ports": ["8000/tcp"]},
                "s": {"mode": "loopback-only", "service_ports": ["8081/tcp"]}}}"#,
        )
        .unwrap();
        let attached = enforce(policy.container("c").unwrap(), &dir, &policy.reserved_ports(), None)
            .expect("attach the loopback-only programs");

        // Built before fork: allocating in the child of a threaded process can deadlock.
        let procs = std::ffi::CString::new(dir.join("cgroup.procs").to_str().unwrap()).unwrap();
        let addr = |ip: [u8; 4], port: u16| libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes(ip) },
            sin_zero: [0; 8],
        };
        let loopback = addr([127, 0, 0, 1], 9);
        let outside = addr([203, 0, 113, 6], 9);
        let route = |hop: u8| [0x83u8, 7, 4, 203, 0, 113, hop, 0];
        let (via_option, via_cmsg) = (route(7), route(8));
        let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        // The child writes its listener ports to `ports`, then waits on `done` for the parent.
        let (mut ports, mut done) = ([0i32; 2], [0i32; 2]);
        assert_eq!(unsafe { libc::pipe(ports.as_mut_ptr()) }, 0);
        assert_eq!(unsafe { libc::pipe(done.as_mut_ptr()) }, 0);
        let wildcard_service = addr([0, 0, 0, 0], 8000);
        // A sibling's undeclared listener on a wildcard address, from outside the cgroup.
        let sibling = std::net::TcpListener::bind("0.0.0.0:0").expect("sibling listener");
        let sibling_port = sibling.local_addr().unwrap().port();
        let mapped = |ip: [u8; 4], port: u16| {
            let mut bytes = [0u8; 16];
            bytes[10..12].copy_from_slice(&[0xff, 0xff]);
            bytes[12..].copy_from_slice(&ip);
            libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: port.to_be(),
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr { s6_addr: bytes },
                sin6_scope_id: 0,
            }
        };
        let (mapped_sibling, mapped_reserved) = (mapped([127, 0, 0, 2], sibling_port), mapped([127, 0, 0, 2], 8081));
        let len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let aliases = [addr([127, 0, 0, 2], sibling_port), addr([0, 0, 0, 0], sibling_port)];
        let reserved_aliases = [addr([127, 0, 0, 2], 8081), addr([0, 0, 0, 0], 8081)];
        // 0.0.0.5 is routed, not local; 127.0.0.2 is local but can be forced onto the wire.
        let zero_net = addr([0, 0, 0, 5], 9);
        let alias = addr([127, 0, 0, 2], 9);
        let mut pktinfo: libc::in_pktinfo = unsafe { std::mem::zeroed() };
        pktinfo.ipi_ifindex = non_loopback_ifindex().expect("a non-loopback device") as i32;

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let code = unsafe {
                let errno = || *libc::__errno_location();
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
                // Writing "0" to cgroup.procs moves the writer itself.
                if fd < 0 || libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                    libc::_exit(10);
                }
                libc::close(fd);
                let udp = || libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                let send = |fd: i32, to: &libc::sockaddr_in| {
                    libc::sendto(fd, b"x".as_ptr().cast(), 1, 0, (to as *const libc::sockaddr_in).cast(), len)
                };
                let plain = udp();
                if send(plain, &loopback) != 1 {
                    libc::_exit(11);
                }
                if send(plain, &outside) != -1 || errno() != libc::EPERM {
                    libc::_exit(12);
                }
                // IP_OPTIONS (4) carrying the source route.
                let routed = udp();
                if libc::setsockopt(routed, libc::IPPROTO_IP, 4, via_option.as_ptr().cast(), 8) != 0 {
                    libc::_exit(13);
                }
                if send(routed, &loopback) != -1 || errno() != libc::EPERM {
                    libc::_exit(14);
                }
                // IP_RETOPTS (7) as a control message: the same route with no setsockopt at all.
                let mut control = [0u64; 8];
                let mut payload = *b"x";
                let mut iov = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: 1 };
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_name = (&loopback as *const libc::sockaddr_in).cast_mut().cast();
                msg.msg_namelen = len;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast();
                msg.msg_controllen = libc::CMSG_SPACE(8) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = 7;
                (*cmsg).cmsg_len = libc::CMSG_LEN(8) as _;
                std::ptr::copy_nonoverlapping(via_cmsg.as_ptr(), libc::CMSG_DATA(cmsg), 8);
                if libc::sendmsg(udp(), &msg, 0) != -1 || errno() != libc::EPERM {
                    libc::_exit(15);
                }
                if send(plain, &zero_net) != -1 || errno() != libc::EPERM {
                    libc::_exit(25);
                }
                // IP_PKTINFO naming the wire device: the kernel skips the local route.
                let mut control = [0u64; 8];
                let mut payload = *b"x";
                let mut iov = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: 1 };
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_name = (&alias as *const libc::sockaddr_in).cast_mut().cast();
                msg.msg_namelen = len;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast();
                let info = std::mem::size_of::<libc::in_pktinfo>() as u32;
                msg.msg_controllen = libc::CMSG_SPACE(info) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(info) as _;
                std::ptr::copy_nonoverlapping(
                    (&pktinfo as *const libc::in_pktinfo).cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    info as usize,
                );
                if libc::sendmsg(udp(), &msg, 0) != -1 || errno() != libc::EPERM {
                    libc::_exit(26);
                }
                // Plain TCP over loopback still works end to end.
                let listener = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                let mut bound = addr([127, 0, 0, 1], 0);
                let mut bound_len = len;
                if libc::bind(listener, (&bound as *const libc::sockaddr_in).cast(), len) != 0
                    || libc::listen(listener, 1) != 0
                    || libc::getsockname(listener, (&mut bound as *mut libc::sockaddr_in).cast(), &mut bound_len) != 0
                {
                    libc::_exit(16);
                }
                let client = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                if libc::connect(client, (&bound as *const libc::sockaddr_in).cast(), len) != 0 {
                    libc::_exit(17);
                }
                // The sibling's unreserved listener is reachable through every local alias, its
                // reserved port through none. The policy refuses with EPERM, not ECONNREFUSED.
                let connect4 = |to: &libc::sockaddr_in| {
                    let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                    let rc = libc::connect(fd, (to as *const libc::sockaddr_in).cast(), len);
                    let error = if rc == 0 { 0 } else { errno() };
                    libc::close(fd);
                    error
                };
                let connect6 = |to: &libc::sockaddr_in6| {
                    let fd = libc::socket(libc::AF_INET6, libc::SOCK_STREAM, 0);
                    let rc = libc::connect(fd, (to as *const libc::sockaddr_in6).cast(), len6);
                    let error = if rc == 0 { 0 } else { errno() };
                    libc::close(fd);
                    error
                };
                for alias in &aliases {
                    if connect4(alias) != 0 {
                        libc::_exit(21);
                    }
                }
                for alias in &reserved_aliases {
                    if connect4(alias) != libc::EPERM {
                        libc::_exit(22);
                    }
                }
                if connect6(&mapped_sibling) != 0 {
                    libc::_exit(23);
                }
                if connect6(&mapped_reserved) != libc::EPERM {
                    libc::_exit(24);
                }
                // listen() without bind() auto-binds 0.0.0.0:<ephemeral> past the bind program.
                let undeclared = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                let mut auto = addr([0, 0, 0, 0], 0);
                let mut auto_len = len;
                if libc::listen(undeclared, 4) != 0
                    || libc::getsockname(undeclared, (&mut auto as *mut libc::sockaddr_in).cast(), &mut auto_len) != 0
                {
                    libc::_exit(18);
                }
                let declared = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
                if libc::bind(declared, (&wildcard_service as *const libc::sockaddr_in).cast(), len) != 0
                    || libc::listen(declared, 4) != 0
                {
                    libc::_exit(19);
                }
                let report = [u16::from_be(auto.sin_port).to_ne_bytes(), 8000u16.to_ne_bytes()];
                if libc::write(ports[1], report.as_ptr().cast(), 4) != 4 {
                    libc::_exit(20);
                }
                let mut byte = 0u8;
                libc::read(done[0], (&mut byte as *mut u8).cast(), 1);
                0
            };
            unsafe { libc::_exit(code) };
        }
        unsafe {
            libc::close(ports[1]);
            libc::close(done[0]);
        }
        let mut report = [0u8; 4];
        let reported = unsafe { libc::read(ports[0], report.as_mut_ptr().cast(), 4) } == 4;
        let mut handshakes = None;
        if reported {
            let undeclared = u16::from_ne_bytes([report[0], report[1]]);
            let declared = u16::from_ne_bytes([report[2], report[3]]);
            // Over a non-loopback address the child's SYN-ACK leaves as one to the host would.
            let local = local_ipv4().expect("a non-loopback IPv4 address");
            let reach = |port: u16| {
                std::net::TcpStream::connect_timeout(
                    &SocketAddr::from((local, port)),
                    Duration::from_secs(2),
                )
                .is_ok()
            };
            handshakes = Some((reach(undeclared), reach(declared)));
        }
        unsafe { libc::write(done[1], [1u8].as_ptr().cast(), 1) };
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        drop(attached);
        drop(sibling);
        let _ = std::fs::remove_dir(&dir);
        assert!(libc::WIFEXITED(status), "child status {:#x}", status);
        // 11 loopback send, 12 outside send, 14/15 IP_OPTIONS/IP_RETOPTS route, 16/17 loopback TCP,
        // 18-20 listeners, 21-24 local aliases (v4, dual-stack), 25 0.0.0.5 send, 26 forced send.
        assert_eq!(libc::WEXITSTATUS(status), 0, "child exit code");
        let (undeclared, declared) = handshakes.expect("the child reported its listeners");
        assert!(!undeclared, "a listener opened without bind() answered a non-loopback peer");
        assert!(declared, "the declared service port must still accept");
    }

    /// In `loopback-only` the own-source-port rule would also drop the forced send, so only this
    /// mode tests the local-destination check alone.
    #[test]
    #[ignore = "requires root, CAP_BPF and a writable cgroup2 hierarchy"]
    fn kernel_backstop_keeps_forced_loopback_sends_on_lo() {
        let dir = PathBuf::from(format!("/sys/fs/cgroup/netpol-test-egress-{}", std::process::id()));
        std::fs::create_dir(&dir).expect("create a scratch cgroup");
        let policy = parse(
            r#"{"version": 1, "containers": {"e": {"mode": "egress-allowlist", "port_allow": ["443/tcp"]}}}"#,
        )
        .unwrap();
        let attached = enforce(policy.container("e").unwrap(), &dir, &policy.reserved_ports(), None)
            .expect("attach the egress-allowlist programs");
        // A cgroup that already has programs is refused.
        let again = enforce(policy.container("e").unwrap(), &dir, &policy.reserved_ports(), None)
            .expect_err("a second policy on the same cgroup");
        assert!(format!("{:#}", again).contains("already has network-policy programs"), "{:#}", again);
        let procs = std::ffi::CString::new(dir.join("cgroup.procs").to_str().unwrap()).unwrap();
        let alias = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 9u16.to_be(),
            sin_addr: libc::in_addr { s_addr: u32::from_ne_bytes([127, 0, 0, 2]) },
            sin_zero: [0; 8],
        };
        let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        let mut pktinfo: libc::in_pktinfo = unsafe { std::mem::zeroed() };
        pktinfo.ipi_ifindex = non_loopback_ifindex().expect("a non-loopback device") as i32;
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let code = unsafe {
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
                if fd < 0 || libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                    libc::_exit(30);
                }
                libc::close(fd);
                let socket = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                let to = (&alias as *const libc::sockaddr_in).cast();
                // Control: the same send on its natural route stays on lo and is allowed.
                if libc::sendto(socket, b"x".as_ptr().cast(), 1, 0, to, len) != 1 {
                    libc::_exit(31);
                }
                let mut control = [0u64; 8];
                let mut payload = *b"x";
                let mut iov = libc::iovec { iov_base: payload.as_mut_ptr().cast(), iov_len: 1 };
                let mut msg: libc::msghdr = std::mem::zeroed();
                msg.msg_name = (&alias as *const libc::sockaddr_in).cast_mut().cast();
                msg.msg_namelen = len;
                msg.msg_iov = &mut iov;
                msg.msg_iovlen = 1;
                msg.msg_control = control.as_mut_ptr().cast();
                let info = std::mem::size_of::<libc::in_pktinfo>() as u32;
                msg.msg_controllen = libc::CMSG_SPACE(info) as _;
                let cmsg = libc::CMSG_FIRSTHDR(&msg);
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(info) as _;
                std::ptr::copy_nonoverlapping(
                    (&pktinfo as *const libc::in_pktinfo).cast::<u8>(),
                    libc::CMSG_DATA(cmsg),
                    info as usize,
                );
                if libc::sendmsg(socket, &msg, 0) != -1 || *libc::__errno_location() != libc::EPERM {
                    libc::_exit(32);
                }
                0
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        // Dropping the guards closes descriptors only; the programs stay on the cgroup.
        drop(attached);
        let cgroup = std::fs::File::open(&dir).expect("open the cgroup");
        let left = attached_program_count(&cgroup, BPF_CGROUP_INET4_CONNECT).expect("query the cgroup");
        drop(cgroup);
        let _ = std::fs::remove_dir(&dir);
        assert_eq!(left, 1, "the connect program outlives its guard");
        assert!(libc::WIFEXITED(status), "child status {:#x}", status);
        // 30 cgroup move, 31 natural loopback send, 32 send forced onto the wire.
        assert_eq!(libc::WEXITSTATUS(status), 0, "child exit code");
    }

    /// A connect to `::ffff:a.b.c.d` runs the IPv6 hook; `::/0` must admit IPv6 only.
    #[test]
    #[ignore = "requires root, CAP_BPF and a writable cgroup2 hierarchy"]
    fn kernel_dual_stack_connects_follow_the_ipv4_rules() {
        let dir = PathBuf::from(format!("/sys/fs/cgroup/netpol-test-mapped-{}", std::process::id()));
        std::fs::create_dir(&dir).expect("create a scratch cgroup");
        let policy = parse(
            r#"{"version": 1, "containers": {"e": {"mode": "egress-allowlist", "port_allow": ["443/tcp"],
                "cidr_allow": ["192.0.2.0/24", "::/0"]}}}"#,
        )
        .unwrap();
        let resolved = std::sync::Arc::new(create_resolved_map().expect("create the resolved map"));
        let attached = enforce(policy.container("e").unwrap(), &dir, &policy.reserved_ports(), Some(resolved))
            .expect("attach the egress-allowlist programs");
        let procs = std::ffi::CString::new(dir.join("cgroup.procs").to_str().unwrap()).unwrap();
        let to = |address: std::net::Ipv6Addr, port: u16| libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr { s6_addr: address.octets() },
            sin6_scope_id: 0,
        };
        let mapped = |ip: [u8; 4]| std::net::Ipv4Addr::from(ip).to_ipv6_mapped();
        // Each destination and whether the policy refuses it.
        let cases = [
            (to(mapped([192, 0, 2, 1]), 443), false),
            (to(mapped([198, 51, 100, 1]), 443), true),
            (to(mapped([192, 0, 2, 1]), 80), true),
            (to("2001:db8::1".parse().unwrap(), 443), false),
        ];
        let len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            let code = unsafe {
                let fd = libc::open(procs.as_ptr(), libc::O_WRONLY);
                if fd < 0 || libc::write(fd, b"0".as_ptr().cast(), 1) != 1 {
                    libc::_exit(30);
                }
                libc::close(fd);
                let mut code = 0;
                for (index, (address, refused)) in cases.iter().enumerate() {
                    // Non-blocking: an allowed connect returns EINPROGRESS or ENETUNREACH at once;
                    // only the policy answers EPERM.
                    let socket = libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_NONBLOCK, 0);
                    let rc = libc::connect(socket, (address as *const libc::sockaddr_in6).cast(), len6);
                    let denied = rc == -1 && *libc::__errno_location() == libc::EPERM;
                    libc::close(socket);
                    if denied != *refused {
                        code = 40 + index as i32;
                        break;
                    }
                }
                code
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        drop(attached);
        let _ = std::fs::remove_dir(&dir);
        assert!(libc::WIFEXITED(status), "child status {:#x}", status);
        // 30 cgroup move failed; 40 + i: `cases[i]` got the other verdict.
        assert_eq!(libc::WEXITSTATUS(status), 0, "child exit code");
    }

    fn non_loopback_ifindex() -> Option<u32> {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut list) } != 0 {
            return None;
        }
        let mut found = None;
        let mut cursor = list;
        while !cursor.is_null() {
            let entry = unsafe { &*cursor };
            if !entry.ifa_addr.is_null()
                && i32::from(unsafe { (*entry.ifa_addr).sa_family }) == libc::AF_INET
                && unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) }.sin_addr.s_addr.to_ne_bytes()[0] != 127
            {
                found = Some(unsafe { libc::if_nametoindex(entry.ifa_name) }).filter(|index| *index != 0);
                break;
            }
            cursor = entry.ifa_next;
        }
        unsafe { libc::freeifaddrs(list) };
        found
    }

    fn local_ipv4() -> Option<[u8; 4]> {
        let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
        if unsafe { libc::getifaddrs(&mut list) } != 0 {
            return None;
        }
        let mut found = None;
        let mut cursor = list;
        while !cursor.is_null() {
            let entry = unsafe { &*cursor };
            if !entry.ifa_addr.is_null()
                && i32::from(unsafe { (*entry.ifa_addr).sa_family }) == libc::AF_INET
            {
                let address = unsafe { &*(entry.ifa_addr as *const libc::sockaddr_in) };
                let octets = address.sin_addr.s_addr.to_ne_bytes();
                if octets[0] != 127 {
                    found = Some(octets);
                    break;
                }
            }
            cursor = entry.ifa_next;
        }
        unsafe { libc::freeifaddrs(list) };
        found
    }

    /// Containers share `init_net`, so a sibling on `0.0.0.0:8000` answers at every local address.
    #[test]
    fn every_local_address_follows_the_loopback_rule() {
        let ports = [
            PortRule::tcp(PortRange::single(443)),
            PortRule { range: PortRange::single(443), protocol: Protocol::Udp },
        ];
        let served = [PortRange::single(8081)];
        // 8000 is a sibling's service port, 53 the stub's.
        let reserved = [53, 8000, 8081];
        let program = egress_allowlist_program(&ports, &[], false, &served, &reserved).expect("policy encodes");
        for local in [[127, 0, 0, 1], [127, 0, 0, 2], [127, 1, 2, 3], [127, 255, 255, 254], [0, 0, 0, 0]] {
            for protocol in [6, 17] {
                assert_eq!(run_proto(&program, 2, local, 8081, protocol), ALLOW, "{:?} own port", local);
                assert_eq!(run_proto(&program, 2, local, 8000, protocol), DENY, "{:?} sibling port", local);
                assert_eq!(run_proto(&program, 2, local, 53, protocol), DENY, "{:?} is not the stub", local);
                assert_eq!(run_proto(&program, 2, local, 29500, protocol), ALLOW, "{:?} ephemeral port", local);
            }
        }
        // The stub answers on port 53 of its own address; other ports there are local.
        assert_eq!(run(&program, 2, [127, 0, 0, 53], 53), ALLOW);
        assert_eq!(run(&program, 2, [127, 0, 0, 53], 8081), ALLOW);
        assert_eq!(run(&program, 2, [127, 0, 0, 53], 8000), DENY);
        // Only the exact 0.0.0.0 is local; the rest of 0.0.0.0/8 is routed out the default route.
        assert_eq!(run(&program, 2, [128, 0, 0, 1], 443), ALLOW, "any non-local address");
        for routed in [[0, 0, 0, 5], [0, 1, 2, 3], [0, 255, 255, 255]] {
            assert_eq!(run_proto(&program, 2, routed, 29500, 17), DENY, "{:?} is not local", routed);
        }
        assert_eq!(run(&program, 2, [126, 255, 255, 255], 8000), DENY, "not in port_allow");
    }

    /// The egress container serves 8081 and may use 443 anywhere; the loopback-only one serves
    /// 8000. Each reserves the other's port.
    #[test]
    fn local_addresses_match_the_spec_matrix() {
        let v6 = |text: &str| text.parse::<std::net::Ipv6Addr>().unwrap().octets();
        let ports = [
            PortRule::tcp(PortRange::single(443)),
            PortRule { range: PortRange::single(443), protocol: Protocol::Udp },
        ];
        let reserved = [53, 8000, 8081];
        let egress4 = egress_allowlist_program(&ports, &[], false, &[PortRange::single(8081)], &reserved).unwrap();
        let egress6 = egress_allowlist_v6_program(&ports, &[], false, &[PortRange::single(8081)], &reserved).unwrap();
        let local4 = loopback_only_program(&[PortRange::single(8000)], &reserved).unwrap();
        let local6 = loopback_only_v6_program(&[PortRange::single(8000)], &reserved).unwrap();
        let locals4 = [[127, 0, 0, 1], [127, 0, 0, 2], [127, 0, 1, 1], [0, 0, 0, 0]];
        let locals6 = ["::1", "::", "::ffff:127.0.0.1", "::ffff:127.9.9.9", "::ffff:0.0.0.0"];
        for protocol in [6u8, 17] {
            for ip in locals4 {
                let verdicts = [
                    (run_proto(&egress4, 2, ip, 8081, protocol), ALLOW, "egress: own port"),
                    (run_proto(&egress4, 2, ip, 8000, protocol), DENY, "egress: sibling port"),
                    (run_proto(&egress4, 2, ip, 40000, protocol), ALLOW, "egress: unreserved port"),
                    (run_proto(&local4, 2, ip, 8000, protocol), ALLOW, "loopback-only: own port"),
                    (run_proto(&local4, 2, ip, 8081, protocol), DENY, "loopback-only: sibling port"),
                    (run_proto(&local4, 2, ip, 40000, protocol), ALLOW, "loopback-only: unreserved port"),
                    (run_proto(&local4, 2, ip, 53, protocol), DENY, "loopback-only: DNS"),
                ];
                for (got, want, case) in verdicts {
                    assert_eq!(got, want, "{} {:?}/{}", case, ip, protocol);
                }
            }
            for text in locals6 {
                let ip = v6(text);
                let verdicts = [
                    (run_v6_proto(&egress6, ip, 8081, protocol), ALLOW, "egress: own port"),
                    (run_v6_proto(&egress6, ip, 8000, protocol), DENY, "egress: sibling port"),
                    (run_v6_proto(&egress6, ip, 40000, protocol), ALLOW, "egress: unreserved port"),
                    (run_v6_proto(&local6, ip, 8000, protocol), ALLOW, "loopback-only: own port"),
                    (run_v6_proto(&local6, ip, 8081, protocol), DENY, "loopback-only: sibling port"),
                    (run_v6_proto(&local6, ip, 40000, protocol), ALLOW, "loopback-only: unreserved port"),
                ];
                for (got, want, case) in verdicts {
                    assert_eq!(got, want, "{} {}/{}", case, text, protocol);
                }
            }
            // The stub, in both spellings, is for the egress container only.
            assert_eq!(run_proto(&egress4, 2, [127, 0, 0, 53], 53, protocol), ALLOW);
            assert_eq!(run_v6_proto(&egress6, v6("::ffff:127.0.0.53"), 53, protocol), ALLOW);
            assert_eq!(run_proto(&local4, 2, [127, 0, 0, 53], 53, protocol), DENY);
            assert_eq!(run_v6_proto(&local6, v6("::ffff:127.0.0.53"), 53, protocol), DENY);
            // The pod address, external addresses and routed 0.0.0.0/8 take the external rule.
            for ip in [[10, 244, 0, 212], [8, 8, 8, 8], [0, 1, 2, 3], [0, 255, 255, 255]] {
                assert_eq!(run_proto(&egress4, 2, ip, 443, protocol), ALLOW, "{:?} on port_allow", ip);
                assert_eq!(run_proto(&egress4, 2, ip, 8000, protocol), DENY, "{:?} off port_allow", ip);
                assert_eq!(run_proto(&local4, 2, ip, 8000, protocol), DENY, "{:?} loopback-only", ip);
            }
            for text in ["2001:db8::1", "::ffff:10.244.0.212", "fe80::1", "::ffff:0.1.2.3"] {
                let ip = v6(text);
                assert_eq!(run_v6_proto(&egress6, ip, 443, protocol), ALLOW, "{} on port_allow", text);
                assert_eq!(run_v6_proto(&egress6, ip, 8000, protocol), DENY, "{} off port_allow", text);
                assert_eq!(run_v6_proto(&local6, ip, 8000, protocol), DENY, "{} loopback-only", text);
            }
        }
    }

    #[test]
    fn dns_stub_is_reachable_without_a_map_entry() {
        let ports = [PortRule::tcp(PortRange::single(443))];
        let program = egress_allowlist_program(&ports, &[], true, &[], &[]).expect("policy encodes");
        let mut c = [0u8; sock_addr::LEN];
        c[0..4].copy_from_slice(&2i32.to_le_bytes());
        c[4..8].copy_from_slice(&[127, 0, 0, 53]);
        c[24..26].copy_from_slice(&53u16.to_be_bytes());
        write_protocol(&mut c, 17);
        assert_eq!(execute_with_resolved(&program, c, &[]), ALLOW, "resolver reachable");
    }

    #[test]
    fn only_address_answers_are_published() {
        // Header: id 0x1234, QR=1, one question, one answer.
        let mut response = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        // QNAME "a.example" + QTYPE A + QCLASS IN
        response.extend_from_slice(&[1, b'a', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]);
        response.extend_from_slice(&[0, 1, 0, 1]);
        // Answer: pointer to the question name, A, IN, TTL 60, rdlength 4, 203.0.113.7
        response.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01]);
        response.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 203, 0, 113, 7]);
        let request = query("a.example");
        assert_eq!(
            answer_addresses(&request, &response),
            vec![(resolved_key(IpAddr::from([203, 0, 113, 7])), 60)]
        );

        // An AAAA answer to an AAAA question: same header and question, new answer record.
        let mut v6 = response[..response.len() - 16].to_vec();
        v6.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01]);
        v6.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c, 0x00, 0x10]);
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        v6.extend_from_slice(&addr);
        let mut request_v6 = request.clone();
        let end = request_v6.len();
        request_v6[end - 3] = 28;
        v6[end - 3] = 28;
        assert_eq!(answer_addresses(&request_v6, &v6), vec![(addr, 60)]);
        assert!(answer_addresses(&request, &v6).is_empty(), "AAAA for an A question");

        // A CNAME answer (type 5) carries no address.
        let mut cname = response[..response.len() - 16].to_vec();
        cname.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01]);
        cname.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c, 0x00, 0x02, 0xc0, 0x0c]);
        assert!(answer_addresses(&request, &cname).is_empty(), "CNAME publishes nothing");

        let truncated = &response[..response.len() - 2];
        assert!(
            answer_addresses(&request, truncated).is_empty(),
            "truncated answer publishes nothing"
        );
    }

    #[test]
    fn dns_and_bind_programs_deny_impersonation() {
        let udp = egress_allowlist_program(&[PortRule::tcp(PortRange::single(443))], &[], true, &[], &[53, 8000, 8081])
            .expect("egress program");
        assert_eq!(run_proto(&udp, 2, [127, 0, 0, 53], 53, 17), ALLOW);
        assert_eq!(run_proto(&udp, 2, [127, 0, 0, 1], 53, 17), DENY);
        assert_eq!(run_proto(&udp, 2, [127, 0, 0, 2], 53, 17), DENY);
        assert_eq!(run_proto(&udp, 2, [127, 0, 0, 53], 8000, 17), DENY, "a sibling's port at the stub address");
        let bind = bind_program(false, &[PortRule::tcp(PortRange::single(8000))], &[53, 8000, 8081]).expect("bind");
        assert_eq!(
            run(&bind, 2, [127, 0, 0, 1], 9000),
            ALLOW,
            "NCCL ephemeral loopback"
        );
        assert_eq!(run(&bind, 2, [127, 0, 0, 1], 0), ALLOW, "ephemeral bind");
        assert_eq!(run(&bind, 2, [127, 0, 0, 1], 8000), ALLOW, "own service");
        assert_eq!(run(&bind, 2, [127, 0, 0, 1], 8081), DENY, "sibling service");
        assert_eq!(run(&bind, 2, [127, 0, 0, 1], 53), DENY, "DNS squatting");
        // Every local address binds like 127.0.0.1.
        assert_eq!(run(&bind, 2, [127, 0, 0, 2], 9000), ALLOW, "another loopback address");
        assert_eq!(run(&bind, 2, [127, 0, 0, 53], 53), DENY, "the stub address");
        assert_eq!(run(&bind, 2, [127, 9, 9, 9], 8081), DENY, "sibling service elsewhere in 127/8");
        assert_eq!(
            run(&bind, 2, [0, 0, 0, 0], 8000),
            ALLOW,
            "declared inbound service"
        );
        assert_eq!(
            run(&bind, 2, [0, 0, 0, 0], 9000),
            DENY,
            "arbitrary wildcard listener"
        );
    }

    #[test]
    fn loopback_only_allows_only_local_addresses() {
        let prog = loopback_only_program(&[PortRange::single(8000)], &[53, 8000, 8081]).expect("policy encodes");
        assert_eq!(run(&prog, 2, [127, 0, 0, 1], 8000), ALLOW, "own listener");
        assert_eq!(run(&prog, 2, [127, 1, 2, 3], 443), ALLOW, "another local address");
        assert_eq!(run(&prog, 2, [0, 0, 0, 0], 9000), ALLOW, "0.0.0.0 is local");
        assert_eq!(run(&prog, 2, [127, 0, 0, 1], 9000), ALLOW, "NCCL peer port");
        assert_eq!(run(&prog, 2, [127, 0, 0, 1], 8081), DENY, "sibling service");
        assert_eq!(run(&prog, 2, [127, 1, 2, 3], 8081), DENY, "sibling service at another local address");
        assert_eq!(run(&prog, 2, [127, 0, 0, 53], 53), DENY, "no DNS for loopback-only");
        assert_eq!(run(&prog, 2, [8, 8, 8, 8], 443), DENY, "public address");
        assert_eq!(run(&prog, 2, [169, 254, 169, 254], 80), DENY, "IMDS");
        assert_eq!(run(&prog, 2, [10, 0, 0, 1], 8000), DENY, "RFC1918 sibling");
        assert_eq!(run(&prog, 2, [192, 168, 1, 1], 443), DENY, "RFC1918");
        assert_eq!(run(&prog, 10, [0, 0, 0, 0], 443), DENY, "AF_INET6");
    }

    #[test]
    fn loopback_only_denies_every_port_on_a_public_address() {
        let prog = loopback_only_program(&[PortRange::single(8000)], &[53, 8000, 8081]).expect("policy encodes");
        for port in [22u16, 53, 80, 443, 8000, 8081, 65535] {
            assert_eq!(run(&prog, 2, [1, 1, 1, 1], port), DENY, "port {port}");
        }
    }

    #[test]
    fn egress_allowlist_allows_configured_ports_to_any_address_when_cidr_is_empty() {
        let prog = egress_allowlist_program(&[PortRule::tcp(PortRange::single(443))], &[], false, &[PortRange::single(8081)], &[]).expect("policy encodes");
        assert_eq!(run(&prog, 2, [34, 120, 45, 54], 443), ALLOW, "NRAS on 443");
        assert_eq!(
            run(&prog, 2, [8, 8, 8, 8], 443),
            ALLOW,
            "any address on 443"
        );
        assert_eq!(
            run(&prog, 2, [169, 254, 169, 254], 443),
            ALLOW,
            "documented default"
        );
        assert_eq!(run(&prog, 2, [8, 8, 8, 8], 80), DENY, "port not listed");
        assert_eq!(run(&prog, 2, [8, 8, 8, 8], 22), DENY, "ssh");
        assert_eq!(
            run(&prog, 10, [0, 0, 0, 0], 443),
            DENY,
            "AF_INET6 is denied"
        );
    }

    #[test]
    fn port_rules_are_protocol_specific() {
        // Without a protocol check, UDP to :443 would pass as TCP: the QUIC-over-443 bypass.
        let tcp_only = [PortRule::tcp(PortRange::single(443))];
        let prog = egress_allowlist_program(&tcp_only, &[], false, &[], &[]).expect("policy encodes");
        assert_eq!(run_proto(&prog, 2, [8, 8, 8, 8], 443, 6), ALLOW, "tcp 443");
        assert_eq!(run_proto(&prog, 2, [8, 8, 8, 8], 443, 17), DENY, "udp 443");

        let udp_only = [PortRule {
            range: PortRange::single(53),
            protocol: Protocol::Udp,
        }];
        let prog = egress_allowlist_program(&udp_only, &[], false, &[], &[]).expect("policy encodes");
        assert_eq!(run_proto(&prog, 2, [8, 8, 8, 8], 53, 17), ALLOW, "udp 53");
        assert_eq!(run_proto(&prog, 2, [8, 8, 8, 8], 53, 6), DENY, "tcp 53");

        let both = [
            PortRule::tcp(PortRange::single(443)),
            PortRule {
                range: PortRange::single(443),
                protocol: Protocol::Udp,
            },
        ];
        let prog = egress_allowlist_program(&both, &[], false, &[], &[]).expect("policy encodes");
        assert_eq!(run_proto(&prog, 2, [8, 8, 8, 8], 443, 6), ALLOW, "tcp");
        assert_eq!(run_proto(&prog, 2, [8, 8, 8, 8], 443, 17), ALLOW, "udp");

        assert_eq!(
            run_proto(&prog, 2, [8, 8, 8, 8], 80, 17),
            DENY,
            "udp on an unlisted port"
        );
    }

    #[test]
    fn egress_allowlist_stub_is_reachable_on_loopback() {
        let prog = egress_allowlist_program(&[PortRule::tcp(PortRange::single(443))], &[], false, &[PortRange::single(8081)], &[]).expect("policy encodes");
        assert_eq!(run(&prog, 2, [127, 0, 0, 53], 53), ALLOW, "the DNS stub");
    }

    #[test]
    fn egress_allowlist_narrows_to_cidr_allow() {
        let cidrs = vec![parse_cidr("34.0.0.0/8").unwrap()];
        let prog = egress_allowlist_program(&[PortRule::tcp(PortRange::single(443))], &cidrs, true, &[PortRange::single(8081)], &[]).expect("policy encodes");
        assert_eq!(
            run(&prog, 2, [34, 120, 45, 54], 443),
            ALLOW,
            "inside cidr_allow"
        );
        assert_eq!(run(&prog, 2, [8, 8, 8, 8], 443), DENY, "outside cidr_allow");
        assert_eq!(
            run(&prog, 2, [169, 254, 169, 254], 443),
            DENY,
            "IMDS excluded"
        );
        // The stub stays reachable even with a populated cidr_allow.
        assert_eq!(run(&prog, 2, [127, 0, 0, 53], 53), ALLOW);
    }

    #[test]
    fn ipv6_uses_all_prefix_bits_and_local_addresses() {
        let mut inside = [0u8; 16];
        inside[..8].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78]);
        inside[8] = 0x80;
        inside[15] = 1;
        let mut outside = inside;
        outside[8] = 0;
        let cidr = [parse_cidr("2001:db8:1234:5678:8000::/65").expect("IPv6 CIDR")];
        let program = egress_allowlist_v6_program(&[PortRule::tcp(PortRange::single(443))], &cidr, true, &[PortRange::single(8081)], &[53, 8000, 8081]).expect("IPv6 program");
        assert_eq!(run_v6(&program, inside, 443), ALLOW, "inside /65");
        assert_eq!(run_v6(&program, outside, 443), DENY, "outside /65");
        assert_eq!(
            run_v6(
                &program,
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                8081
            ),
            ALLOW
        );
        assert_eq!(
            run_v6(
                &program,
                [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                8000
            ),
            DENY
        );
        let empty = egress_allowlist_v6_program(&[PortRule::tcp(PortRange::single(443))], &[], false, &[], &[]).expect("empty IPv6 CIDRs");
        assert_eq!(run_v6(&empty, outside, 443), ALLOW);
        let local =
            loopback_only_v6_program(&[PortRange::single(8000)], &[53, 8000, 8081]).expect("loopback IPv6 program");
        let mut mapped = [0u8; 16];
        mapped[10] = 0xff;
        mapped[11] = 0xff;
        mapped[12..].copy_from_slice(&[127, 0, 0, 1]);
        assert_eq!(run_v6(&local, mapped, 8000), ALLOW, "dual-stack loopback reaches the own port");
        assert_eq!(run_v6(&local, mapped, 8081), DENY, "but not a sibling's");
    }

    #[test]
    fn socket_creation_excludes_ping_raw_and_other_ip_protocols() {
        fn verdict(family: i32, typ: i32, protocol: i32) -> i64 {
            let mut ctx = [0u8; sock_addr::LEN];
            ctx[4..8].copy_from_slice(&family.to_le_bytes());
            ctx[8..12].copy_from_slice(&typ.to_le_bytes());
            ctx[12..16].copy_from_slice(&protocol.to_le_bytes());
            execute(&ip_socket_create_program().unwrap(), ctx)
        }
        for family in [2, 10] {
            assert_eq!(verdict(family, libc::SOCK_STREAM, 0), ALLOW);
            assert_eq!(
                verdict(family, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 6),
                ALLOW
            );
            assert_eq!(verdict(family, libc::SOCK_DGRAM, 17), ALLOW);
            assert_eq!(
                verdict(family, libc::SOCK_DGRAM | libc::SOCK_NONBLOCK, 0),
                ALLOW
            );
            assert_eq!(verdict(family, libc::SOCK_DGRAM, 1), DENY, "ping socket");
            assert_eq!(
                verdict(family, libc::SOCK_DGRAM, 58),
                DENY,
                "IPv6 ping socket"
            );
            assert_eq!(verdict(family, libc::SOCK_RAW, 6), DENY);
            assert_eq!(
                verdict(family, libc::SOCK_STREAM, 262),
                DENY,
                "explicit MPTCP"
            );
            assert_eq!(verdict(family, libc::SOCK_STREAM, 132), DENY, "SCTP");
            assert_eq!(verdict(family, libc::SOCK_DGRAM, 136), DENY, "UDPLite");
            assert_eq!(verdict(family, libc::SOCK_STREAM, 33), DENY, "DCCP");
        }
        assert_eq!(verdict(libc::AF_UNIX, libc::SOCK_STREAM, 0), DENY);
    }

    #[test]
    #[cfg(feature = "seccomp")]
    fn podvm_filter_denies_sniffing_but_keeps_netlink_and_tcp() {
        // Deprecated in libc, but denying it is the point.
        #[allow(deprecated)]
        const SOCK_PACKET: i32 = libc::SOCK_PACKET;
        // Seccomp cannot be unloaded, so load it in a child that exits without destructors.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork: {}", std::io::Error::last_os_error());
        if pid == 0 {
            if rustjail::seccomp::init_podvm_network_seccomp().is_err() {
                unsafe { libc::_exit(1) };
            }
            for (domain, typ, protocol) in [
                (libc::AF_INET, libc::SOCK_STREAM, 0),
                (libc::AF_INET, libc::SOCK_DGRAM, 0),
                (libc::AF_INET6, libc::SOCK_STREAM, 0),
                // vLLM's engine and ZMQ channels are Unix sockets.
                (libc::AF_UNIX, libc::SOCK_STREAM, 0),
                // CUDA's `cuInit` opens this one (error 304 when denied).
                (libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0),
                // `getifaddrs(3)` uses this; NCCL and Gloo need it to pick a device.
                (libc::AF_NETLINK, libc::SOCK_RAW, 0),
            ] {
                let fd = unsafe { libc::socket(domain, typ, protocol) };
                if fd < 0 {
                    unsafe { libc::_exit(2) };
                }
                unsafe { libc::close(fd) };
            }
            // The family rules deny no type but SOCK_RAW and SOCK_PACKET.
            for domain in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK] {
                for typ in 1..=15 {
                    if typ == SOCK_PACKET || (typ == libc::SOCK_RAW && domain != libc::AF_NETLINK) {
                        continue;
                    }
                    let fd = unsafe { libc::socket(domain, typ | libc::SOCK_CLOEXEC, 0) };
                    if fd >= 0 {
                        unsafe { libc::close(fd) };
                    } else if std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
                        unsafe { libc::_exit(5) };
                    }
                }
            }
            for (domain, typ, protocol) in [
                (libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP),
                (libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6),
                (libc::AF_PACKET, libc::SOCK_RAW, 0),
                (libc::AF_PACKET, libc::SOCK_DGRAM, 0),
                // Legacy packet capture: the kernel turns this into a packet socket.
                (libc::AF_INET, SOCK_PACKET, i32::from((libc::ETH_P_ALL as u16).to_be())),
                // vsock reaches the host; AF_ALG needs no privilege, so its EPERM is the filter's.
                (libc::AF_VSOCK, libc::SOCK_STREAM, 0),
                (libc::AF_ALG, libc::SOCK_SEQPACKET, 0),
            ] {
                let fd = unsafe { libc::socket(domain, typ, protocol) };
                if fd >= 0 {
                    unsafe { libc::close(fd) };
                    unsafe { libc::_exit(3) };
                }
                if std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
                    unsafe { libc::_exit(4) };
                }
            }
            unsafe { libc::_exit(0) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "child status {:#x}", status);
        assert_eq!(libc::WEXITSTATUS(status), 0, "child status {:#x}", status);
    }

    /// Loads the programs but attaches to no cgroup.
    #[test]
    #[ignore = "requires CAP_BPF on the target kernel"]
    fn kernel_verifier_accepts_the_compiled_programs() {
        let v4 = parse_cidr("198.51.100.128/25").unwrap();
        let v6 = parse_cidr("2001:db8:1234:5678:8000::/65").unwrap();
        // The longest lists cost the verifier the most: it walks every loop iteration.
        let most_v4: Vec<Cidr> = (0..MAX_CIDR4)
            .map(|index| parse_cidr(&format!("10.{}.{}.0/24", index / 256, index % 256)).unwrap())
            .collect();
        let most_v6: Vec<Cidr> = (0..MAX_CIDR6)
            .map(|index| parse_cidr(&format!("2001:db8:{index:x}::/48")).unwrap())
            .collect();
        let https = [PortRule::tcp(PortRange::single(443))];
        let programs = [
            (
                "create",
                BPF_PROG_TYPE_CGROUP_SOCK,
                BPF_CGROUP_INET_SOCK_CREATE,
                ip_socket_create_program().unwrap(),
            ),
            (
                "connect4",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET4_CONNECT,
                loopback_only_program(&[PortRange::single(8000)], &[53, 8000, 8081]).unwrap(),
            ),
            (
                "connect6",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET6_CONNECT,
                loopback_only_v6_program(&[PortRange::single(8000)], &[53, 8000, 8081]).unwrap(),
            ),
            (
                "udp",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_UDP4_SENDMSG,
                egress_allowlist_program(&https, &[v4], true, &[PortRange::single(8081)], &[53, 8000, 8081]).unwrap(),
            ),
            (
                "egress4",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET4_CONNECT,
                egress_allowlist_program(&https, &[v4], true, &[PortRange::single(8081)], &[]).unwrap(),
            ),
            (
                "egress6",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET6_CONNECT,
                egress_allowlist_v6_program(&https, &[v6], false, &[PortRange::single(8081)], &[]).unwrap(),
            ),
            (
                "egress-backstop",
                BPF_PROG_TYPE_CGROUP_SKB,
                BPF_CGROUP_INET_EGRESS,
                egress_backstop_program(&[PortRule::tcp(PortRange::single(8000)), PortRule::tcp(PortRange { start: 9000, end: 9002 })], false).unwrap(),
            ),
            (
                "egress-backstop-loopback-only",
                BPF_PROG_TYPE_CGROUP_SKB,
                BPF_CGROUP_INET_EGRESS,
                egress_backstop_program(
                    &[PortRule::tcp(PortRange::single(8000)), PortRule { range: PortRange::single(5353), protocol: Protocol::Udp }],
                    true,
                )
                .unwrap(),
            ),
            // An explicit "any" in both families.
            (
                "egress4-any",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET4_CONNECT,
                egress_allowlist_program(&https, &[parse_cidr("0.0.0.0/0").unwrap()], true, &[], &[]).unwrap(),
            ),
            (
                "egress6-any",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET6_CONNECT,
                egress_allowlist_v6_program(&https, &[parse_cidr("::/0").unwrap()], true, &[], &[]).unwrap(),
            ),
            (
                "egress6-resolved",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET6_CONNECT,
                egress_allowlist_v6_program(&https, &[v6], true, &[PortRange::single(8081)], &[]).unwrap(),
            ),
            (
                "udp6-resolved",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_UDP6_SENDMSG,
                egress_allowlist_v6_program(&[PortRule { range: PortRange::single(443), protocol: Protocol::Udp }], &[], true, &[], &[]).unwrap(),
            ),
            (
                "egress4-most-prefixes",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET4_CONNECT,
                egress_allowlist_program(&https, &most_v4, true, &[], &[]).unwrap(),
            ),
            (
                "egress6-most-prefixes",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET6_CONNECT,
                egress_allowlist_v6_program(&https, &most_v6, true, &[], &[]).unwrap(),
            ),
            // A dual-stack connect to ::ffff:a.b.c.d walks the IPv4 list from the IPv6 hook.
            (
                "egress6-most-ipv4-prefixes",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET6_CONNECT,
                egress_allowlist_v6_program(&https, &most_v4, true, &[], &[]).unwrap(),
            ),
            (
                "bind4",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET4_BIND,
                bind_program(false, &[PortRule::tcp(PortRange::single(8000))], &[53, 8000, 8081]).unwrap(),
            ),
            (
                "bind6",
                BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                BPF_CGROUP_INET6_BIND,
                bind_program(true, &[PortRule::tcp(PortRange::single(8000))], &[53, 8000, 8081]).unwrap(),
            ),
        ];
        // Load as `attach` does, with real maps: only the kernel catches a bad map reference.
        use std::os::fd::AsRawFd;
        let resolved = create_resolved_map().expect("create the resolved map");
        let mut failures = Vec::new();
        for (name, prog_type, attach_type, program) in programs {
            let policy = create_policy_map(&program.policy).expect("create the policy map");
            let fds = [resolved.as_raw_fd(), policy.as_raw_fd()];
            let mut log = vec![0u8; VERIFIER_LOG_LEN];
            let fd = unsafe { prog_load(prog_type, attach_type, program.insns, &object().license, &mut log, &fds) };
            if let Err(error) = fd {
                let log = String::from_utf8_lossy(&log);
                failures.push(format!("{name}: {error}: {}", log.trim_matches('\0').trim()));
            }
        }
        assert!(failures.is_empty(), "verifier rejected:\n{}", failures.join("\n"));
    }

    /// A minimal type-A query for `name`.
    fn query(name: &str) -> Vec<u8> {
        let mut msg = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: RD
            0x00, 0x01, // qdcount
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
        ];
        for label in name.split('.') {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE A, QCLASS IN
        msg
    }

    #[test]
    fn parse_qname_extracts_the_question() {
        assert_eq!(
            parse_qname(&query("nras.attestation.nvidia.com")).as_deref(),
            Some("nras.attestation.nvidia.com")
        );
        assert_eq!(
            parse_qname(&query("Example.COM")).as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn parse_qname_rejects_malformed_queries() {
        // Too short for a header.
        assert!(parse_qname(&[0u8; 5]).is_none());
        // Zero questions.
        let mut no_questions = query("example.com");
        no_questions[5] = 0;
        assert!(parse_qname(&no_questions).is_none());
        // Truncated label.
        let mut truncated = query("example.com");
        truncated.truncate(14);
        assert!(parse_qname(&truncated).is_none());
        // Compression pointer in the question is not followed.
        let mut compressed = query("example.com");
        compressed[12] = 0xc0;
        assert!(parse_qname(&compressed).is_none());
    }

    #[test]
    fn name_allowed_is_case_insensitive_and_ignores_a_trailing_dot() {
        let allow = BTreeSet::from(["nras.attestation.nvidia.com".to_string()]);
        assert!(name_allowed(&allow, "nras.attestation.nvidia.com"));
        assert!(name_allowed(&allow, "NRAS.Attestation.NVIDIA.com"));
        assert!(name_allowed(&allow, "nras.attestation.nvidia.com."));
        assert!(!name_allowed(&allow, "example.com"));
        assert!(!name_allowed(
            &allow,
            "nras.attestation.nvidia.com.evil.test"
        ));
    }

    #[test]
    fn upstream_responses_must_match_the_transaction_and_question() {
        let original = query("nras.attestation.nvidia.com");
        let mut response = original.clone();
        response[2] |= 0x80;
        assert!(response_matches_query(&original, &response));
        let unmatched_id = &response;
        let mut wrong = unmatched_id.clone();
        wrong[0] ^= 1;
        assert!(!response_matches_query(&original, &wrong));
        let other_name = query("example.com");
        wrong = other_name;
        wrong[2] |= 0x80;
        assert!(!response_matches_query(&original, &wrong));
        wrong = response.clone();
        wrong.truncate(wrong.len() - 1);
        assert!(!response_matches_query(&original, &wrong));
        let truncated = &original[..original.len() - 1];
        assert_eq!(
            parse_qname(truncated),
            None,
            "missing QCLASS must not forward"
        );
        assert_eq!(&refused_response(truncated)[4..6], &[0, 0]);
    }

    #[test]
    fn resolver_records_and_duplicate_policy_names_reject_ambiguity() {
        let records = [
            "search example.test".to_string(),
            "nameserver 10.0.2.3".to_string(),
            "nameserver 10.0.2.4:5353".to_string(),
        ];
        assert_eq!(
            parse_upstreams(&records).expect("real resolv.conf records"),
            vec![
                "10.0.2.3:53".parse().unwrap(),
                "10.0.2.4:5353".parse().unwrap(),
            ]
        );
        assert!(parse_upstreams(&["10.0.2.3".to_string()]).is_err());
        assert!(parse_upstreams(&["nameserver".to_string()]).is_err());
        let duplicate = VLLM.replace(
            r#""attestation": {"#,
            r#""vllm": {"mode": "loopback-only", "service_ports": [8001]},
            "attestation": {"#,
        );
        let error = policy(&duplicate).expect_err("duplicate container");
        assert!(
            format!("{:#}", error).contains("duplicate container"),
            "{:#}",
            error
        );
        let ambiguous_dns = VLLM.replace(
            r#""nras.attestation.nvidia.com""#,
            r#""nras.attestation.nvidia.com", "NRAS.ATTESTATION.NVIDIA.COM.""#,
        );
        assert!(policy(&ambiguous_dns).is_err());
    }

    async fn bind_udp_eventually(
        addr: SocketAddr,
    ) -> Result<tokio::net::UdpSocket, std::io::Error> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::net::UdpSocket::bind(addr).await {
                Ok(socket) => return Ok(socket),
                Err(error) if tokio::time::Instant::now() < deadline => {
                    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{error}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn bind_tcp_eventually(
        addr: SocketAddr,
    ) -> Result<tokio::net::TcpListener, std::io::Error> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => return Ok(listener),
                Err(error) if tokio::time::Instant::now() < deadline => {
                    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{error}");
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn dns_filter_authenticates_replies_and_stops_owned_tasks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let upstream =
            std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let address = upstream.local_addr().unwrap();
        let tcp_upstream = tokio::net::TcpListener::bind(address).await.unwrap();
        let served_upstream = upstream.clone();
        let served = tokio::spawn(async move {
            let upstream = served_upstream;
            let mut query = vec![0u8; DNS_MAX_MESSAGE];
            let (length, peer) = upstream.recv_from(&mut query).await.unwrap();
            query.truncate(length);
            let mut wrong = query.clone();
            wrong[0] ^= 0xff;
            upstream.send_to(&wrong, peer).await.unwrap();
            let mut answer = query.clone();
            assert_eq!(answer[0], 0x12);
            answer[2] |= 0x80;
            upstream.send_to(&answer, peer).await.unwrap();
            let (mut stream, _) = tcp_upstream.accept().await.unwrap();
            let mut size = [0u8; 2];
            stream.read_exact(&mut size).await.unwrap();
            let mut query = vec![0u8; usize::from(u16::from_be_bytes(size))];
            stream.read_exact(&mut query).await.unwrap();
            query[2] |= 0x80;
            stream
                .write_all(&(query.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&query).await.unwrap();
        });
        let filter = start_dns_filter(
            BTreeSet::from(["nras.attestation.nvidia.com".to_string()]),
            vec![address],
            None,
        )
        .await
        .expect("stub binds");
        let stub = SocketAddr::from(([127, 0, 0, 53], 53));
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = query("nras.attestation.nvidia.com");
        client.send_to(&request, stub).await.unwrap();
        let mut response = vec![0u8; DNS_MAX_MESSAGE];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut response))
                .await
                .expect("authentic upstream response")
                .unwrap();
        response.truncate(length);
        assert!(
            response_matches_query(&request, &response),
            "wrong-ID spoof was accepted"
        );
        client.send_to(&query("example.com"), stub).await.unwrap();
        let (length, _) = client.recv_from(&mut response).await.unwrap();
        assert!(length >= DNS_HEADER_LEN);
        assert_eq!(response[3] & 0xf, DNS_RCODE_REFUSED);

        let mut tcp = tokio::net::TcpStream::connect(stub).await.unwrap();
        tcp.write_all(&(request.len() as u16).to_be_bytes())
            .await
            .unwrap();
        tcp.write_all(&request).await.unwrap();
        let mut size = [0u8; 2];
        tcp.read_exact(&mut size).await.unwrap();
        let mut response = vec![0u8; usize::from(u16::from_be_bytes(size))];
        tcp.read_exact(&mut response).await.unwrap();
        assert!(response_matches_query(&request, &response));
        served.await.unwrap();
        // Leave a worker pending: `stop()` must await its cloned UDP socket too.
        client.send_to(&request, stub).await.unwrap();
        let mut pending = vec![0u8; DNS_MAX_MESSAGE];
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut pending))
                .await
                .expect("forwarding worker becomes pending")
                .unwrap();
        assert_eq!(&pending[..length], &request);
        filter.stop().await;
        // The port frees shortly after the last close, not at once.
        let udp = bind_udp_eventually(stub).await.expect("UDP released");
        let tcp = bind_tcp_eventually(stub).await.expect("TCP released");
        drop((udp, tcp, client));
    }

    #[test]
    fn only_allowlisted_names_are_forwarded() {
        let allow = BTreeSet::from(["nras.attestation.nvidia.com".to_string()]);
        assert!(should_forward(
            &allow,
            &query("nras.attestation.nvidia.com")
        ));
        assert!(!should_forward(&allow, &query("example.com")));
        assert!(!should_forward(&allow, &query("attestation.nvidia.com")));
        assert!(!should_forward(&allow, &[0u8; 3]));
    }

    #[test]
    fn refused_response_sets_qr_and_rcode() {
        let query = query("example.com");
        let response = refused_response(&query);
        assert_eq!(response.len(), query.len(), "echoes the question");
        assert_eq!(response[0..2], query[0..2], "same id");
        assert_eq!(response[2] & 0x80, 0x80, "QR set");
        assert_eq!(response[3] & 0x0f, DNS_RCODE_REFUSED, "RCODE REFUSED");
        assert_eq!(&response[6..12], &[0u8; 6], "no answer records");
    }

    #[test]
    fn refused_response_is_empty_for_a_non_query() {
        assert!(refused_response(&[0u8; 4]).is_empty());
    }

    #[test]
    fn empty_cidr_allow_allows_everything() {
        // No destination axis at all: permissive by decision, not oversight.
        assert!(address_allowed(
            &[],
            false,
            [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            false
        ));
        // Including IMDS and RFC1918.
        assert!(address_allowed(
            &[],
            false,
            [169, 254, 169, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            false
        ));
        assert!(address_allowed(
            &[],
            false,
            [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            false
        ));
    }

    #[test]
    fn populated_cidr_allow_narrows() {
        let cidrs = vec![parse_cidr("34.120.0.0/16").unwrap()];
        let inside = [34, 120, 45, 54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let outside = [169, 254, 169, 254, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(address_allowed(&cidrs, true, inside, false));
        assert!(!address_allowed(&cidrs, true, outside, false));
    }

    #[test]
    fn cidr_prefixes_match_on_bit_boundaries() {
        let cidr = parse_cidr("10.0.0.0/12").unwrap();
        assert!(cidr.contains([10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(cidr.contains([10, 15, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!cidr.contains([10, 16, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        let odd = parse_cidr("192.168.1.0/25").unwrap();
        assert!(odd.contains([192, 168, 1, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!odd.contains([192, 168, 1, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn v6_prefixes_do_not_match_v4_addresses() {
        let cidrs = vec![parse_cidr("2001:db8::/32").unwrap()];
        let v4 = [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!address_allowed(&cidrs, true, v4, false));
    }

    #[test]
    fn destination_axis_exists_when_either_list_is_present() {
        let parse = |json: &str| policy(json).expect("policy parses").containers
            .values().next().cloned().expect("one container");

        let neither = parse(r#"{"version": 1, "containers": {
            "c": {"mode": "egress-allowlist", "port_allow": ["443/tcp"]}}}"#);
        assert!(!neither.destination_axis(), "ports alone decide");

        let cidr_only = parse(r#"{"version": 1, "containers": {
            "c": {"mode": "egress-allowlist", "port_allow": ["443/tcp"],
                  "cidr_allow": ["10.0.0.0/8"]}}}"#);
        assert!(cidr_only.destination_axis());

        // `dns_allow` alone still constrains destinations: the DNS filter admits the resolved ones.
        let dns_only = parse(r#"{"version": 1, "containers": {
            "c": {"mode": "egress-allowlist", "port_allow": ["443/tcp"],
                  "dns_allow": ["nras.attestation.nvidia.com"]}}}"#);
        assert!(dns_only.destination_axis(), "dns_allow alone constrains");
        let empty: Vec<Cidr> = Vec::new();
        assert!(
            !address_allowed(&empty, dns_only.destination_axis(), [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false),
            "a dns_allow-only axis must not fall back to any address"
        );
        assert!(
            address_allowed(&empty, neither.destination_axis(), [8, 8, 8, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false),
            "no axis means any address"
        );
    }

    #[test]
    fn rejects_malformed_cidrs() {
        for bad in [
            "10.0.0.0",
            "10.0.0.0/33",
            "::/129",
            "not-an-ip/8",
            "10.0.0.0/",
            // Host bits: these read like one host and admit a /8, everything, a /64.
            "10.0.0.5/8",
            "8.8.8.8/0",
            "2001:db8::1/64",
            // Sign or padding that `u8::from_str` would accept.
            "10.0.0.0/+8",
            "10.0.0.0/0008",
        ] {
            assert!(parse_cidr(bad).is_err(), "{} should not parse", bad);
        }
        let error = parse_cidr("10.0.0.5/8").unwrap_err();
        assert!(format!("{:#}", error).contains("10.0.0.0/8"), "{:#}", error);
        // IPv4-mapped prefixes would never match: the programs judge those addresses as IPv4.
        let error = parse_cidr("::ffff:10.0.0.0/104").unwrap_err();
        assert!(format!("{:#}", error).contains("write it as 10.0.0.0/8"), "{:#}", error);
        assert!(parse_cidr("::ffff:0:0/96").is_err());
        for good in ["0.0.0.0/0", "::/0", "10.0.0.5/32", "10.0.0.0/8", "2001:db8::/32", "198.51.100.128/25"] {
            parse_cidr(good).unwrap();
        }
    }

    #[test]
    fn explicit_any_prefixes_assemble_and_admit_their_family() {
        let ports = [PortRule::tcp(PortRange::single(443))];
        let v4 = egress_allowlist_program(&ports, &[parse_cidr("0.0.0.0/0").unwrap()], true, &[], &[]).expect("0.0.0.0/0");
        assert_eq!(run(&v4, 2, [203, 0, 113, 9], 443), ALLOW);
        let v6 = egress_allowlist_v6_program(&ports, &[parse_cidr("::/0").unwrap()], true, &[], &[]).expect("::/0");
        let mut anywhere = [0u8; 16];
        anywhere[0] = 0x20;
        anywhere[15] = 9;
        assert_eq!(run_v6(&v6, anywhere, 443), ALLOW);
        // The agreed spelling for "any address": both families together.
        let both = [parse_cidr("0.0.0.0/0").unwrap(), parse_cidr("::/0").unwrap()];
        egress_allowlist_program(&ports, &both, true, &[], &[]).expect("IPv4 program");
        egress_allowlist_v6_program(&ports, &both, true, &[], &[]).expect("IPv6 program");
    }

    /// One resource record: owner name bytes (labels or a pointer), type, then RDATA.
    fn record(owner: &[u8], rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut out = owner.to_vec();
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
        out
    }

    fn labels(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// A response to `query("nras.attestation.nvidia.com")` with these section counts and records.
    fn upstream_response(an: u16, ns: u16, ar: u16, records: &[u8]) -> Vec<u8> {
        let mut out = query("nras.attestation.nvidia.com");
        out[2] = 0x81;
        out[3] = 0x80;
        out[6..8].copy_from_slice(&an.to_be_bytes());
        out[8..10].copy_from_slice(&ns.to_be_bytes());
        out[10..12].copy_from_slice(&ar.to_be_bytes());
        out.extend_from_slice(records);
        out
    }

    #[test]
    fn a_cgroup_enforced_for_one_container_is_refused_for_another() {
        let base = std::env::temp_dir().join(format!("net-policy-cgroups-{}", std::process::id()));
        let (first, second) = (base.join("first"), base.join("second"));
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        // Only the cgroup descriptor matters to the check; `/dev/null` stands in for the program.
        let attached = Attached {
            prog_fd: std::fs::File::open("/dev/null").unwrap().into(),
            cgroup_fd: std::fs::File::open(&first).unwrap().into(),
            _map: None,
        };
        let mut containers = std::collections::HashMap::new();
        containers.insert("vllm".to_string(), vec![attached]);
        containers.insert("unenforced".to_string(), Vec::new());
        let err = check_cgroup_unshared(&first, &containers).unwrap_err();
        assert!(format!("{:#}", err).contains("container vllm"), "{:#}", err);
        // Another spelling of the same directory is still the same cgroup.
        assert!(check_cgroup_unshared(&base.join("second/../first"), &containers).is_err());
        check_cgroup_unshared(&second, &containers).expect("a cgroup of its own");
        drop(containers);
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn upstream_query_carries_the_question_and_nothing_else() {
        let canonical = query("nras.attestation.nvidia.com");
        assert_eq!(upstream_query(&canonical).unwrap(), canonical, "a plain query is unchanged");
        // Mixed case, the AD and CD bits, an answer, an EDNS record with a payload, and trailing
        // bytes: all of it goes, and only the lowercased question is left.
        let mut padded = query("NRAS.Attestation.NVIDIA.com");
        padded[3] = 0x30;
        padded[7] = 1;
        padded[11] = 1;
        padded.extend_from_slice(&record(&[0xc0, 0x0c], 1, &[1, 2, 3, 4]));
        let mut opt = vec![0u8];
        opt.extend_from_slice(&41u16.to_be_bytes());
        opt.extend_from_slice(&[0x10, 0, 0, 0, 0, 0]);
        opt.extend_from_slice(&904u16.to_be_bytes());
        opt.extend_from_slice(&65001u16.to_be_bytes());
        opt.extend_from_slice(&900u16.to_be_bytes());
        opt.extend_from_slice(&[b'X'; 900]);
        padded.extend_from_slice(&opt);
        padded.extend_from_slice(b"trailing");
        assert_eq!(upstream_query(&padded).unwrap(), canonical);
        // Types the filter does not forward stay refused.
        let mut txt = canonical.clone();
        let end = txt.len();
        txt[end - 3] = 16;
        assert!(upstream_query(&txt).is_none());
    }

    #[test]
    fn only_the_chain_of_the_queried_type_is_published() {
        let request = query("nras.attestation.nvidia.com");
        let cdn = labels("edge.cdn.example");
        let mut answers = record(&[0xc0, 0x0c], 5, &cdn);
        // The CNAME target sits right after the question and the first record's fixed fields.
        let target = (request.len() + 2 + 10) as u16;
        let target_pointer = (0xc000 | target).to_be_bytes();
        answers.extend(record(&target_pointer, 1, &[34, 120, 45, 54]));
        answers.extend(record(&labels("unrelated.example"), 1, &[6, 6, 6, 6]));
        answers.extend(record(&[0xc0, 0x0c], 16, b"\x05hello"));
        answers.extend(record(&target_pointer, 28, &[0x20; 16]));
        let response = upstream_response(5, 0, 0, &answers);
        assert_eq!(
            answer_addresses(&request, &response),
            vec![(resolved_key(IpAddr::from([34, 120, 45, 54])), 60)],
            "only the chain's address is published, not the unrelated owner's or the AAAA"
        );
    }

    #[test]
    fn publishing_follows_long_pointers_and_refuses_loops() {
        let request = query("nras.attestation.nvidia.com");
        // Push the CNAME target past offset 255, which a pointer can only reach with 0xc1 or more.
        let target_name = format!("{}.cdn.example", "a".repeat(60));
        let filler = record(&[0xc0, 0x0c], 16, &[b'x'; 200]);
        let mut records = filler.clone();
        let cname_at = request.len() + records.len();
        records.extend(record(&[0xc0, 0x0c], 5, &labels(&target_name)));
        let target = (cname_at + 2 + 10) as u16;
        assert!(target > 255);
        records.extend(record(&(0xc000 | target).to_be_bytes(), 1, &[34, 120, 45, 54]));
        assert_eq!(
            answer_addresses(&request, &upstream_response(3, 0, 0, &records)),
            vec![(resolved_key(IpAddr::from([34, 120, 45, 54])), 60)],
            "a pointer past 255 is followed"
        );
        // A pointer to itself, or forwards, publishes nothing instead of looping.
        let here = request.len() as u16;
        let looping = record(&(0xc000 | here).to_be_bytes(), 1, &[1, 2, 3, 4]);
        assert!(answer_addresses(&request, &upstream_response(1, 0, 0, &looping)).is_empty());
        let forward = record(&(0xc000 | (here + 40)).to_be_bytes(), 1, &[1, 2, 3, 4]);
        assert!(answer_addresses(&request, &upstream_response(1, 0, 0, &forward)).is_empty());
    }

    #[test]
    fn client_gets_the_upstream_answer_with_its_own_id_and_question() {
        let request = query("NRAS.Attestation.NVIDIA.com");
        let mut client = request.clone();
        client[0..2].copy_from_slice(&[0xab, 0xcd]);
        let mut records = record(&[0xc0, 0x0c], 16, b"\x05hello");
        records.extend(record(&labels("nvidia.com"), 2, &labels("ns.nvidia.com")));
        let mut response = upstream_response(1, 1, 0, &records);
        response[3] = 0x83;
        let returned = client_response(&client, &response).expect("same question");
        let mut expected = response.clone();
        expected[0..2].copy_from_slice(&[0xab, 0xcd]);
        expected[DNS_HEADER_LEN..request.len()].copy_from_slice(&request[DNS_HEADER_LEN..]);
        assert_eq!(
            returned, expected,
            "the upstream answer, NXDOMAIN and every record included, with the client's id and case"
        );
        assert!(response_matches_query(&client, &returned), "answers the client's question");
        // A response to some other question is not passed off as this one's.
        let other = upstream_response(0, 0, 0, &[]);
        assert!(client_response(&query("other.example"), &other).is_none());
    }

    #[tokio::test]
    async fn identical_questions_in_flight_share_one_upstream_request() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let forwarding = Forwarding::default();
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let ask = |forwarding: Forwarding, asked: std::sync::Arc<AtomicUsize>, id: u8, name: &'static str| async move {
            let mut client = query(name);
            client[0..2].copy_from_slice(&[0, id]);
            let upstream = upstream_query(&client).unwrap();
            forward_merged(&forwarding, upstream, move |upstream| async move {
                asked.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(50)).await;
                // An echo: the reply carries the id of the client whose request went upstream.
                Some(upstream)
            })
            .await
        };
        let mut burst = tokio::task::JoinSet::new();
        for id in 0..20u8 {
            burst.spawn(ask(forwarding.clone(), asked.clone(), id, "nras.attestation.nvidia.com"));
        }
        burst.spawn(ask(forwarding.clone(), asked.clone(), 99, "other.example"));
        let mut answers = BTreeSet::new();
        while let Some(answer) = burst.join_next().await {
            answers.insert(answer.unwrap().expect("every client is answered"));
        }
        assert_eq!(asked.load(Ordering::SeqCst), 2, "one upstream request per distinct question");
        assert_eq!(answers.len(), 2, "the burst shares one answer");
        let state = forwarding.lock().unwrap();
        assert!(state.in_flight.is_empty(), "nothing stays in flight once answered");
        // The echo has no answer records, so it is not cached and the next question asks again.
        assert!(state.answers.is_empty());
        drop(state);
        ask(forwarding.clone(), asked.clone(), 1, "nras.attestation.nvidia.com").await.unwrap();
        assert_eq!(asked.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn a_published_address_lives_as_long_as_its_shortest_link() {
        let request = query("nras.attestation.nvidia.com");
        let with_ttl = |mut record: Vec<u8>, owner_len: usize, ttl: u32| {
            record[owner_len + 4..owner_len + 8].copy_from_slice(&ttl.to_be_bytes());
            record
        };
        // A 30 s CNAME leading to a 600 s address: the address goes stale with the alias.
        let mut records = with_ttl(record(&[0xc0, 0x0c], 5, &labels("edge.cdn.example")), 2, 30);
        let target = (request.len() + 2 + 10) as u16;
        records.extend(with_ttl(record(&(0xc000 | target).to_be_bytes(), 1, &[34, 120, 45, 54]), 2, 600));
        assert_eq!(
            answer_addresses(&request, &upstream_response(2, 0, 0, &records)),
            vec![(resolved_key(IpAddr::from([34, 120, 45, 54])), 30)]
        );
    }

    #[tokio::test]
    async fn complete_answers_are_served_from_the_cache_until_their_ttl() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let forwarding = Forwarding::default();
        let asked = std::sync::Arc::new(AtomicUsize::new(0));
        let answer = |rcode: u8, ttl: u32| {
            let mut response = upstream_response(1, 0, 0, &record(&[0xc0, 0x0c], 1, &[34, 120, 45, 54]));
            response[3] |= rcode;
            let end = response.len();
            response[end - 10..end - 6].copy_from_slice(&ttl.to_be_bytes());
            response
        };
        let ask = |forwarding: Forwarding, asked: std::sync::Arc<AtomicUsize>, name: &'static str, reply: Vec<u8>| async move {
            forward_merged(&forwarding, upstream_query(&query(name)).unwrap(), move |_| async move {
                asked.fetch_add(1, Ordering::SeqCst);
                Some(reply)
            })
            .await
        };
        let first = ask(forwarding.clone(), asked.clone(), "nras.attestation.nvidia.com", answer(0, 60)).await;
        let again = ask(forwarding.clone(), asked.clone(), "nras.attestation.nvidia.com", answer(0, 60)).await;
        assert_eq!(asked.load(Ordering::SeqCst), 1, "the second question is answered from the cache");
        assert_eq!(first, again);
        let upstream = upstream_query(&query("nras.attestation.nvidia.com")).unwrap();
        assert!(cached_answer(&forwarding, &upstream).is_some());
        // Expired answers are not served.
        forwarding.lock().unwrap().answers.values_mut().for_each(|(_, expiry)| *expiry = std::time::Instant::now());
        assert!(cached_answer(&forwarding, &upstream).is_none());
        // Errors, zero TTLs and truncated answers always go upstream again.
        for (name, reply) in [
            ("servfail.example", answer(2, 60)),
            ("zero.example", answer(0, 0)),
            ("truncated.example", {
                let mut reply = answer(0, 60);
                reply[2] |= 0x02;
                reply
            }),
        ] {
            assert_eq!(cache_ttl(&reply), None, "{}", name);
        }
        assert_eq!(cache_ttl(&answer(0, 7200)), Some(RESOLVED_MAX_TTL), "TTLs are capped");
    }

    #[test]
    fn dns_allow_is_lowercased_across_containers() {
        let parsed = policy(VLLM).unwrap();
        assert_eq!(
            parsed.dns_allow(),
            BTreeSet::from(["nras.attestation.nvidia.com".to_string()])
        );
    }

    #[test]
    fn resolve_cgroup_uses_procfs_for_systemd_and_init_subgroups() {
        let manager = Path::new("/sys/fs/cgroup/system.slice/kata_agent-abc.scope");
        let (dir, relative) =
            resolve_cgroup_dir(manager, "0::/system.slice/kata_agent-abc.scope\n")
                .expect("real systemd scope");
        assert_eq!(dir, manager);
        assert_eq!(relative, "/system.slice/kata_agent-abc.scope");

        let manager = Path::new("/sys/fs/cgroup/abc");
        let (dir, relative) =
            resolve_cgroup_dir(manager, "0::/abc/init\n").expect("cgroupfs init child");
        assert_eq!(dir, PathBuf::from("/sys/fs/cgroup/abc/init"));
        assert_eq!(relative, "/abc/init");
        assert!(resolve_cgroup_dir(manager, "0::/other\n").is_err());
        assert!(resolve_cgroup_dir(manager, "0::/\n").is_err());
    }

    #[test]
    fn cgroup_membership_reads_the_v2_line() {
        assert_eq!(cgroup_membership("0::/abc\n").unwrap(), "/abc");
        assert_eq!(cgroup_membership("0::/kata/abc").unwrap(), "/kata/abc");
        assert!(cgroup_membership("").is_err());
        // A cgroup v1 line is not a v2 membership.
        assert!(cgroup_membership("12:cpu,cpuacct:/abc\n").is_err());
    }

    #[test]
    fn verify_placement_accepts_a_placed_process() {
        verify_placement("/abc", "0::/abc\n", "4242\n", 4242).expect("placed");
        verify_placement("/abc", "0::/abc/", " 4242 \n", 4242).expect("normalised");
    }

    #[test]
    fn verify_placement_rejects_the_unplaced_case() {
        // rustjail skipped `cm.apply()`: the process is still in the root cgroup.
        let error = verify_placement("/abc", "0::/\n", "1\n", 4242)
            .expect_err("root cgroup must be rejected");
        let message = error.to_string();
        assert!(message.contains("is in cgroup /"), "{}", message);
        assert!(message.contains("expected /abc"), "{}", message);
    }

    #[test]
    fn verify_placement_rejects_a_missing_pid() {
        let error =
            verify_placement("/abc", "0::/abc", "1\n2\n", 4242).expect_err("pid must be listed");
        assert!(error.to_string().contains("does not list"), "{}", error);
    }
}
