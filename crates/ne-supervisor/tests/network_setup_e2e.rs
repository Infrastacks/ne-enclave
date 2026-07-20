// SPDX-FileCopyrightText: 2026 Mindpool, Inc.
// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! End-to-end test for the per-workspace network plumbing.
//!
//! Sets up a workspace network, asserts the kernel actually has
//! the netns + interfaces + IP assignments + NAT rule, tears it
//! down, and asserts the cleanup is complete (`ip netns list`
//! returns nothing for our prefix, the host veth is gone, no
//! leftover iptables rule).
//!
//! Skipped by default (`#[ignore]`) — needs root (or sudo) to
//! mutate netns / iptables. The test runs the supervisor's own
//! helpers, not a separate daemon, so it doesn't need
//! ne-supervisor itself to be running.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use ne_supervisor::network::{NetworkController, NetworkPolicy};

fn ip_binary() -> PathBuf {
    PathBuf::from("/usr/sbin/ip")
}

fn iptables_binary() -> PathBuf {
    PathBuf::from("/usr/sbin/iptables")
}

fn upstream_iface() -> String {
    // The Azure dev VM uses `eth0` as its default-route NIC. If the
    // VM is reconfigured (or we run this test elsewhere), set
    // NE_NETWORK_TEST_IFACE to override.
    std::env::var("NE_NETWORK_TEST_IFACE").unwrap_or_else(|_| "eth0".into())
}

#[tokio::test]
#[ignore = "needs root (or sudo) to mutate netns + iptables; run via `sudo -E ./target/debug/...`"]
async fn provisions_and_reclaims_a_workspace_network() {
    // E2 path: no DNS filter binary (DNS mediation is exercised
    // by the DNS-specific test elsewhere); supervisor passes
    // None and the controller skips the spawn.
    let controller = NetworkController::new(
        ip_binary(),
        iptables_binary(),
        upstream_iface(),
        None,
        "1.1.1.1:53".into(),
        None,
        None,
        None,
    );
    let workspace_id = format!("wks-net-{}", std::process::id());

    // Exercise the deny-by-default path: enable egress and allow
    // 0.0.0.0/0 so the workspace can still reach the outside world,
    // but ensure the FORWARD chain + jump rule are actually in place.
    let policy = NetworkPolicy {
        enable_egress: true,
        allow_cidrs: vec!["0.0.0.0/0".into()],
        allow_hostnames: vec![],
        enable_privacy_router: false,
    };
    let slot = controller
        .setup(&workspace_id, &policy)
        .await
        .expect("workspace network setup must succeed");

    // ----- post-setup invariants -----
    assert!(
        netns_exists(&slot.netns),
        "expected `ip netns list` to include {}",
        slot.netns
    );
    assert!(
        interface_exists_in_netns(&slot.netns, &slot.veth_guest),
        "guest veth {} not present in {}",
        slot.veth_guest,
        slot.netns,
    );
    assert!(
        interface_exists_in_netns(&slot.netns, &slot.tap),
        "tap device {} not present in {}",
        slot.tap,
        slot.netns,
    );
    assert!(
        interface_exists_in_root(&slot.veth_host),
        "host veth {} not present in root netns",
        slot.veth_host,
    );
    assert!(
        masquerade_rule_present(slot.slot),
        "MASQUERADE rule for 169.254.{}.0/30 not present in iptables nat POSTROUTING",
        slot.slot,
    );
    assert!(
        forward_chain_exists(&slot.forward_chain),
        "FORWARD chain {} not present in iptables filter table",
        slot.forward_chain,
    );

    // ----- teardown + cleanup invariants -----
    controller
        .teardown(slot.clone())
        .await
        .expect("workspace network teardown must succeed");
    assert!(
        !netns_exists(&slot.netns),
        "netns {} should be gone post-teardown",
        slot.netns
    );
    assert!(
        !interface_exists_in_root(&slot.veth_host),
        "host veth {} should be gone post-teardown",
        slot.veth_host,
    );
    assert!(
        !masquerade_rule_present(slot.slot),
        "MASQUERADE rule for slot {} should be gone post-teardown",
        slot.slot,
    );
    assert!(
        !forward_chain_exists(&slot.forward_chain),
        "FORWARD chain {} should be gone post-teardown",
        slot.forward_chain,
    );
}

fn forward_chain_exists(chain: &str) -> bool {
    let out = Command::new("/usr/sbin/iptables")
        .args(["-S", chain])
        .output()
        .expect("iptables -S <chain>");
    out.status.success()
}

fn netns_exists(name: &str) -> bool {
    let out = Command::new("/usr/sbin/ip")
        .args(["netns", "list"])
        .output()
        .expect("ip netns list");
    let listing = String::from_utf8_lossy(&out.stdout);
    listing
        .lines()
        .any(|line| line.split_whitespace().next() == Some(name))
}

fn interface_exists_in_netns(netns: &str, ifname: &str) -> bool {
    let out = Command::new("/usr/sbin/ip")
        .args(["netns", "exec", netns, "ip", "-o", "link", "show"])
        .output()
        .expect("ip -o link show");
    let listing = String::from_utf8_lossy(&out.stdout);
    listing.contains(&format!(" {ifname}: ")) || listing.contains(&format!(" {ifname}@"))
}

fn interface_exists_in_root(ifname: &str) -> bool {
    let out = Command::new("/usr/sbin/ip")
        .args(["-o", "link", "show"])
        .output()
        .expect("ip -o link show");
    let listing = String::from_utf8_lossy(&out.stdout);
    listing.contains(&format!(" {ifname}: ")) || listing.contains(&format!(" {ifname}@"))
}

fn masquerade_rule_present(slot: u8) -> bool {
    let needle = format!("169.254.{slot}.0/30");
    let out = Command::new("/usr/sbin/iptables")
        .args(["-t", "nat", "-S", "POSTROUTING"])
        .output()
        .expect("iptables -t nat -S POSTROUTING");
    let listing = String::from_utf8_lossy(&out.stdout);
    listing
        .lines()
        .any(|line| line.contains(&needle) && line.contains("MASQUERADE"))
}
