import json
from pathlib import Path
import unittest

import test_podvm

ROOT = test_podvm.ROOT


class NetPolicyTests(unittest.TestCase):
    """Source-level guards; the agent's behavior is tested in Rust (assets/agent-net-policy.rs)."""

    def setUp(self):
        self.module = (ROOT / "assets/agent-net-policy.rs").read_text()
        self.programs = (ROOT / "assets/net-policy.bpf.c").read_text()
        self.patch = (ROOT / "assets/patches/kata-net-policy.patch").read_text()

    def test_agent_patch_is_wired_into_the_build(self):
        source = (ROOT / "podvm.py").read_text()
        self.assertIn("kata-net-policy.patch", source)
        self.assertIn("agent-net-policy.rs", source)
        order = source[source.index("def patch_agent"):]
        order = order[:order.index("shutil.copy2")]
        self.assertLess(
            order.index("kata-model-mounts.patch"), order.index("kata-net-policy.patch"),
            "net-policy must apply after model-mounts, which it follows in main.rs",
        )
        self.assertIn("agent_net_policy_patch_sha256", source)
        self.assertIn("agent_net_policy_module_sha256", source)

    def test_ebpf_programs_are_compiled_by_the_locked_toolchain(self):
        source = (ROOT / "podvm.py").read_text()
        self.assertIn('kata / "src/agent/src/net_policy.bpf.c"', source)
        self.assertIn('include_bytes!("net_policy.bpf.o")', self.module)
        for key in ("agent_net_policy_programs_sha256", "agent_net_policy_object_sha256"):
            self.assertIn(key, source)
        dockerfile = (ROOT / "assets/model-builder.Dockerfile").read_text()
        install = dockerfile[dockerfile.index("snapshot.debian.org"):dockerfile.index("rm -rf /var/lib/apt/lists")]
        for package in ("clang-16", "linux-libc-dev"):
            self.assertIn(f" {package}", install)
        build = (ROOT / "assets/build-model-components.sh").read_text()
        self.assertIn("clang-16 -target bpfel", build)
        self.assertIn("-c src/net_policy.bpf.c -o src/net_policy.bpf.o", build)
        self.assertIn("-nostdinc", build)
        self.assertLess(build.index("net_policy.bpf.o"), build.index("cargo test"),
                        "the object must exist before the module that embeds it is compiled")
        # The agent loads the object with bpf(2) itself, without a loader crate.
        for crate in ("aya", "libbpf"):
            self.assertNotIn(f"use {crate}", self.module)

    def test_patch_fixes_the_conditional_cgroup_apply(self):
        # Upstream ran apply() only when resources were present.
        self.assertIn("-    if res.is_some() {", self.patch)
        self.assertIn("+    cm.apply(p.pid)?;", self.patch)
        # set() stays conditional to keep the systemd ordering rule.
        self.assertIn("if let Some(resource) = res {", self.patch)

    def test_sandbox_checks_policy_targets_against_the_agent_policy(self):
        self.assertIn("pub fn check_targets", self.module)
        prepare = self.module[self.module.index("pub fn prepare"):]
        self.assertIn("check_targets(&policy, rego)?;", prepare[:prepare.index("\n}\n")])
        self.assertIn("net_policy::prepare(parsed, rego, net_policy::write_sysctl)", self.patch)
        self.assertIn("data._policy.as_deref()", self.patch)

    def test_refused_policy_is_reported_not_fatal(self):
        self.assertIn("net_policy_error", self.patch)
        self.assertIn("net_policy::refusal(&reason)", self.patch)
        self.assertIn("net_policy::refusal(reason)", self.patch)
        self.assertIn("net_policy::prepare(parsed, rego, net_policy::write_sysctl)", self.patch)
        self.assertNotIn(".map(|value| crate::net_policy::parse(value))\n+            .transpose()?", self.patch)
        source = (ROOT / "podvm.py").read_text()
        self.assertIn("def smoke_network_policy_refusal", source)
        self.assertIn("smoke_network_policy_refusal(temporary", source[source.index("def smoke("):])
        for scenario in ("netpol-malformed", "netpol-stray-entry"):
            self.assertIn(scenario, source)

    def test_agent_asserts_placement_after_start(self):
        self.assertIn("verify_placement", self.module)
        self.assertIn("cgroup.procs", self.module)
        self.assertIn("check_placement", self.patch)
        self.assertIn("/proc/{pid}/cgroup", self.patch)
        # Check before attaching, so an enforced container can't take over another's cgroup.
        body = self.patch[self.patch.index("let enforced = policy.container(&policy_name)"):]
        self.assertLess(body.index("check_cgroup_unshared(&cgroup_dir, &s.net_attachments)"),
                        body.index("net_policy::enforce(entry"))

    def test_reserved_ports_are_derived(self):
        self.assertIn("pub fn reserved_ports", self.module)
        self.assertNotIn("pub reserved_ports", self.module)
        self.assertIn("DNS_STUB_PORT", self.module)

    def test_patch_uses_policy_identity_and_real_cgroup_manager(self):
        self.assertIn("k8s::container_name(&oci)", self.patch)
        self.assertIn("policy.container(&policy_name)", self.patch)
        self.assertIn('get_cgroup_path("")', self.patch)
        self.assertIn("resolve_cgroup_dir", self.patch)
        self.assertIn("OwnedFd", self.module)
        # Never detached, so a process that outlives its container stays enforced.
        self.assertNotIn("BPF_PROG_DETACH", self.module)
        self.assertIn("attached_program_count(&cgroup, BPF_CGROUP_INET4_CONNECT)", self.module)
        self.assertIn("use_sandbox_pidns && !s.net_policy.containers.is_empty()", self.patch)
        self.assertIn("network-policy.json needs the agent policy (policy.rego)", self.module)

    def test_specials_cidr_deny_absent(self):
        self.assertNotIn("cidr_deny", self.module)
        self.assertIn("pub cidr_allow", self.module)

    def test_destination_axis_gates_address_allowed(self):
        # Empty cidr_allow must not mean "any": dns_allow-only policies admit via the resolver.
        body = self.module[self.module.index("pub fn address_allowed"):]
        body = body[:body.index("\n}\n")]
        self.assertIn("if !constrained {", body)
        self.assertIn("return true;", body)
        self.assertNotIn("if cidrs.is_empty() {", body)

    def test_dns_filter_refuses_by_default_and_publishes_answers(self):
        self.assertIn("pub fn parse_qname", self.module)
        self.assertIn("pub fn should_forward", self.module)
        self.assertIn("DNS_RCODE_REFUSED", self.module)
        self.assertIn("pub fn answer_addresses", self.module)
        self.assertIn("pub fn publish_resolved", self.module)
        self.assertIn("BPF_MAP_TYPE_LRU_HASH", self.module)
        # Only A/AAAA records of the queried type, on the queried name's CNAME chain, are published.
        self.assertIn("(1, 1, 4) if qtype == 1", self.module)
        self.assertIn("(1, 28, 16) if qtype == 28", self.module)
        self.assertIn(".filter(|(owner, _, _)| chain.contains(owner))", self.module)
        # Published addresses expire with their TTL.
        self.assertIn("BPF_FUNC_KTIME_GET_NS", self.module)
        self.assertIn("RESOLVED_MIN_TTL", self.module)
        # An unparseable query is refused, not forwarded.
        self.assertIn("None => false", self.module)
        filter_body = self.module[self.module.index("async fn udp_loop"):]
        self.assertLess(
            filter_body.index("publish_resolved"),
            filter_body.index("client.send_to"),
            "publish before the client sees the answer",
        )

    def test_enforcement_attaches_both_connect_and_sendmsg(self):
        # Unconnected UDP skips the connect hooks; without sendmsg, QUIC and DNS egress stay open.
        for hook in ("INET_SOCK_CREATE", "INET4_CONNECT", "INET6_CONNECT", "INET4_BIND",
                     "INET6_BIND", "UDP4_SENDMSG", "UDP6_SENDMSG"):
            self.assertIn(f"BPF_CGROUP_{hook}", self.module)
        enforcement = self.module[self.module.index("pub fn enforce"):]
        enforcement = enforcement[:enforcement.index("\n}\n")]
        self.assertLess(enforcement.index("BPF_CGROUP_INET_SOCK_CREATE"),
                        enforcement.index("BPF_CGROUP_INET4_CONNECT)?;"))
        self.assertIn("&programs.sock_create", enforcement)
        for hook, program in (("INET4_CONNECT", "outbound4"), ("INET6_CONNECT", "outbound6"),
                              ("UDP4_SENDMSG", "outbound4"), ("UDP6_SENDMSG", "outbound6"),
                              ("INET4_BIND", "bind4"), ("INET6_BIND", "bind6")):
            self.assertIn(f"install(&programs.{program}, BPF_PROG_TYPE_CGROUP_SOCK_ADDR, BPF_CGROUP_{hook})",
                          enforcement)
        # Backstop: a source route sends to a first hop the connect/sendmsg programs never saw.
        self.assertIn("install(&programs.egress, BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS)",
                      enforcement)
        # The policy map is frozen before any program that reads it is loaded.
        self.assertLess(enforcement.index("create_policy_map(&encoded)"), enforcement.index("install("))
        self.assertIn("BPF_MAP_FREEZE", self.module)
        self.assertIn("BPF_F_RDONLY_PROG", self.module)
        # Ping sockets are datagrams but not UDP, so the UDP sendmsg hooks would miss them.
        create = self.programs[self.programs.index('SEC("netpol/sock_create")'):]
        create = create[:create.index("\n}\n")]
        self.assertIn("protocol == 0 || protocol == IPPROTO_UDP", create)
        self.assertIn("protocol == 0 || protocol == IPPROTO_TCP", create)
        self.assertIn("init_podvm_network_seccomp", self.patch)
        self.assertIn("ScmpCompareOp::MaskedEqual(0xf)", self.patch)
        self.assertIn("set_act_badarch(ScmpAction::KillProcess)", self.patch)

    def test_loopback_address_is_compared_in_network_byte_order(self):
        # user_ip4 is __be32: on a little-endian target the first octet is the low byte.
        self.assertIn("return (ip & BE32(0xff000000)) == BE32(0x7f000000);", self.programs)
        self.assertIn("#define BE32(value) ((__be32)__builtin_bswap32(value))", self.programs)
        self.assertIn('#error "the address and port constants below assume a little-endian BPF target"',
                      self.programs)

    def test_every_local_address_follows_the_loopback_rule(self):
        # Containers share init_net, so every local address reaches a sibling bound to 0.0.0.0.
        for name in ('SEC("netpol/outbound4")', 'SEC("netpol/outbound6")'):
            body = self.programs[self.programs.index(name):]
            body = body[:body.index("\n}\n")]
            self.assertIn("v4_is_local_destination(", body, name)
            self.assertLess(body.index("return loopback_rule(port);"),
                            body.index("if (mode == MODE_LOOPBACK_ONLY)"), name)
            self.assertLess(body.index("return loopback_rule(port);"), body.index("port_allowed("), name)
        self.assertIn("every_local_address_follows_the_loopback_rule", self.module)
        self.assertIn("local_addresses_match_the_spec_matrix", self.module)

    def test_dns_stub_binds_loopback_only(self):
        self.assertIn('SocketAddr::from(([127, 0, 0, 53], DNS_STUB_PORT))', self.module)
        self.assertIn('"127.0.0.53"', self.module)

    def test_at_most_one_allowlist_container(self):
        self.assertIn("at most one container may use egress-allowlist", self.module)

    def test_sysctl_values(self):
        self.assertIn('("kernel.io_uring_disabled", "2")', self.module)
        self.assertIn('("user.max_user_namespaces", "0")', self.module)

    def test_dns_upstreams_come_from_the_sandbox_resolver(self):
        self.assertIn("parse_upstreams", self.module)
        self.assertNotIn("pub upstreams: Vec<SocketAddr>,\n}", self.module,
                         "dns.upstreams must not be a policy field")
        self.assertIn("dns_records", self.patch)
        self.assertIn("parse_upstreams(&resolver_records)", self.patch)

    def test_absent_policy_is_not_deny_all(self):
        self.assertNotIn("unwrap_or_else(net_policy::Policy::deny_all)", self.module)

    def test_policy_document_shape(self):
        policy = {
            "version": 1,
            "containers": {
                "vllm": {"mode": "loopback-only", "service_ports": ["8000/tcp"]},
                "attestation": {
                    "mode": "egress-allowlist",
                    "service_ports": ["8081/tcp"],
                    "dns_allow": ["nras.attestation.nvidia.com"],
                    "port_allow": ["443/tcp"],
                    "cidr_allow": [],
                },
            },
        }
        for field in ("mode", "service_ports", "dns_allow", "port_allow", "cidr_allow"):
            self.assertIn(field, self.module, f"{field} must be a policy field")
        # The resolver bind follows from the mode; the policy must not name a path.
        self.assertNotIn("resolv_conf: Option", self.module)
        # A container without a resolv.conf mount is refused, not left on the image's resolver.
        self.assertIn("has no /etc/resolv.conf mount to point at the network-policy DNS filter", self.patch)
        self.assertNotIn("building the filtered resolver mount", self.patch)
        # Entries are a port or "start-end" range, optionally /tcp or /udp; tcp_allow is gone.
        self.assertIn("struct PortRange", self.module)
        self.assertIn("struct PortRule", self.module)
        self.assertIn("fn parse_port", self.module)
        self.assertNotIn("TcpAllow", self.module)
        self.assertEqual(json.loads(json.dumps(policy)), policy)


if __name__ == "__main__":
    unittest.main()
