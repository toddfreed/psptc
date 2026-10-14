#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""
PSP tunnel mode hardware offload (tc psp action), between two hosts.

Both ends put their device in switchdev mode and create a VF, moved to a
netns. On each end, all in hardware (skip_sw):

  VF representor ingress:
    tunnel_key set (outer addresses) + psp encap mode tunnel + mirred to
    the uplink: the device encrypts the VF's packets and adds the outer
    IP + UDP + PSP headers.
  uplink ingress, matching the local Rx SPI, PSP version and device:
    psp decap mode tunnel + vlan push_eth + mirred to the representor:
    the device decrypts, strips the outer headers and the trailer, and
    writes an L2 header for the VF.

The two VFs then talk to each other through the tunnel, with inner IPv4
and IPv6, including UDP datagrams over the VF MTU, which the sender
fragments. The outer header uses the address family the env is set up
with.

Needs on both ends: a PSP capable device which supports tc tunnel mode
offload in switchdev mode (for mlx5: flow_steering_mode dmfs, which the
test sets), SR-IOV, tc with the psp action, and python3. The remote also
needs the ynl CLI, to set up its associations.
"""

import json
import os
import time
from contextlib import ExitStack
from pathlib import Path

from lib.py import ksft_run, ksft_exit, ksft_pr, ksft_eq, ksft_ge, ksft_true
from lib.py import ksft_variants, KsftNamedVariant, KsftSkipEx
from lib.py import NetDrvEpEnv, PSPFamily, NlError, CmdExitFailure
from lib.py import bkg, cmd, defer, ip, wait_port_listen

# Inner addresses - TEST-NET-2 (RFC 5737) / doc prefix (RFC 3849)
INNER = {
    "4": ("198.51.100.1", "198.51.100.2", 24),
    "6": ("2001:db8:100::1", "2001:db8:100::2", 64),
}
VF_MAC = ("02:00:00:50:53:01", "02:00:00:50:53:02")
# Source MAC of decapsulated packets, and what the VFs send to
GW_MAC = "02:00:00:50:53:fe"
PSP_PORT = 1000
# Outer IP + UDP + PSP header + ICV
TUN_OVERHEAD = {"4": 20 + 8 + 16 + 16, "6": 40 + 8 + 16 + 16}
PREF = 10
PING_CNT = 20
UDP_PORT = 7601
UDP_CNT = 10

# Receive datagrams on a port for a while, print their sizes
UDP_RECV = r"""
import select, socket, sys, time
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
s.bind(("", int(sys.argv[2])))
sizes = []
end = time.time() + float(sys.argv[3])
while time.time() < end:
    if select.select([s], [], [], 0.1)[0]:
        sizes.append(len(s.recv(65535)))
print(" ".join(map(str, sizes)))
"""

# Send datagrams of the given sizes
UDP_SEND = r"""
import socket, sys, time
fam = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM)
for size in map(int, sys.argv[4:]):
    s.sendto(b"x" * size, (sys.argv[2], int(sys.argv[3])))
    time.sleep(0.01)
"""


def _spec_path():
    ksft_dir = Path(__file__).resolve().parents[3]
    for spec in (ksft_dir / "net/lib/specs/psp.yaml",
                 ksft_dir / "../../../Documentation/netlink/specs/psp.yaml"):
        if spec.exists():
            return spec.resolve().as_posix()
    raise KsftSkipEx("PSP YNL spec not found")


def _key_from_hex(obj):
    if isinstance(obj.get("key"), str):
        obj["key"] = bytes.fromhex(obj["key"])
    return obj


class End:
    """
    One end of the tunnel: the uplink and its PSP device, the VF (in a
    netns) and its representor.
    """

    def __init__(self, cfg, idx):
        self.idx = idx
        self.remote = idx == 1
        self.host = cfg.remote if self.remote else None
        self.ifname = cfg.remote_ifname if self.remote else cfg.ifname
        self.vf_mac = VF_MAC[idx]
        self.pci = None
        self.vf_pci = None
        self.vf = None
        self.rep = None
        self.netns = None
        self.psp_dev_id = None
        self.decap_match = None
        self.pspnl = None
        self.spec = None

    def __str__(self):
        return "remote" if self.remote else "local"

    def sh(self, comm, **kwargs):
        return cmd(comm, shell=True, host=self.host, **kwargs)

    def devlink_json(self, args):
        return json.loads(self.sh(f"devlink -j {args}").stdout)

    # PSP netlink: PSPFamily locally, the ynl CLI on the remote

    def psp(self, op, req, dump=False):
        if not self.remote:
            fn = getattr(self.pspnl, op.replace("-", "_"))
            return fn(req, dump=True) if dump else fn(req)
        # The CLI takes and prints binary attributes (keys) as hex strings
        kind = "--dump" if dump else "--do"
        req = json.dumps(req, default=bytes.hex)
        out = self.sh(f"ynl --spec {self.spec} --no-schema {kind} {op} "
                      f"--json '{req}' --output-json").stdout
        return json.loads(out, object_hook=_key_from_hex) if out.strip() else None

    def stats(self):
        return self.psp("get-stats", {"dev-id": self.psp_dev_id})

    def rx_spi_alloc(self, version):
        rx = self.psp("rx-spi-alloc", {"dev-id": self.psp_dev_id,
                                       "version": version})
        defer(self.assoc_del, rx["id"])
        return rx

    def assoc_add(self, version, key):
        tx = self.psp("assoc-add", {"dev-id": self.psp_dev_id,
                                    "version": version, "tx-key": key})
        defer(self.assoc_del, tx["id"])
        return tx

    def assoc_del(self, assoc_id):
        try:
            self.psp("assoc-del", {"id": assoc_id})
        except NlError:
            pass

    def rule_stats(self, dev, pref=PREF):
        """in_hw and the packet count of the filter on @dev ingress @pref"""
        out = cmd(f"tc -s -j filter show dev {dev} ingress pref {pref}",
                  host=self.host).stdout
        for flt in json.loads(out):
            opts = flt.get("options")
            if not opts:
                continue
            pkts = max(act.get("stats", {}).get("packets", 0)
                       for act in opts.get("actions", []))
            return opts.get("in_hw", False), pkts
        return False, 0

    def rule_hits(self, dev, want, pref=PREF):
        """
        Packet count of a filter, waiting for it to reach @want: drivers
        refresh offloaded filter stats periodically.
        """
        for _ in range(30):
            _, pkts = self.rule_stats(dev, pref)
            if pkts >= want:
                break
            time.sleep(0.1)
        return pkts


def _setup_end(stack, cfg, end):
    """switchdev mode, a VF in a netns, and the PSP device of the uplink"""
    end.pci = os.path.basename(end.sh(
        f"readlink -f /sys/class/net/{end.ifname}/device").stdout.strip())
    dev = f"pci/{end.pci}"

    total = int(end.sh(
        f"cat /sys/class/net/{end.ifname}/device/sriov_totalvfs",
        fail=False).stdout.strip() or 0)
    if total < 1:
        raise KsftSkipEx(f"{end}: {end.ifname} has no SR-IOV")
    mode = end.devlink_json(f"dev eswitch show {dev}")["dev"][dev]["mode"]
    if mode != "legacy":
        raise KsftSkipEx(f"{end}: eswitch is in {mode} mode, expected legacy")

    # mlx5 can only offload PSP in switchdev with firmware steering
    params = end.devlink_json(f"dev param show {dev} name flow_steering_mode")
    if "param" in params:
        fsm = params["param"][dev][0]["values"][0]["value"]
        if fsm != "dmfs":
            end.sh(f"devlink dev param set {dev} name flow_steering_mode "
                   "value dmfs cmode runtime")
            stack.callback(end.sh, f"devlink dev param set {dev} name "
                           f"flow_steering_mode value {fsm} cmode runtime")

    numvfs = f"/sys/class/net/{end.ifname}/device/sriov_numvfs"
    end.sh(f"echo 1 > {numvfs}")
    stack.callback(end.sh, f"echo 0 > {numvfs}")
    end.vf_pci = os.path.basename(end.sh(
        f"readlink -f /sys/class/net/{end.ifname}/device/virtfn0").stdout.strip())
    ip(f"link set dev {end.ifname} vf 0 mac {end.vf_mac}", host=end.host)

    # The VF's driver has to come back after the mode change to get a
    # representor-backed VF
    drv = os.path.basename(end.sh(
        f"readlink -f /sys/bus/pci/devices/{end.vf_pci}/driver").stdout.strip())
    end.sh(f"echo {end.vf_pci} > /sys/bus/pci/drivers/{drv}/unbind")
    try:
        end.sh(f"devlink dev eswitch set {dev} mode switchdev")
    except Exception as exc:
        end.sh(f"echo {end.vf_pci} > /sys/bus/pci/drivers/{drv}/bind",
               fail=False)
        raise KsftSkipEx(f"{end}: can't enable switchdev mode") from exc
    stack.callback(end.sh, f"devlink dev eswitch set {dev} mode legacy")
    end.sh(f"echo {end.vf_pci} > /sys/bus/pci/drivers/{drv}/bind")

    for _ in range(50):
        out = end.sh(f"ls /sys/bus/pci/devices/{end.vf_pci}/net",
                     fail=False).stdout.split()
        if out:
            end.vf = out[0]
            break
        time.sleep(0.2)
    else:
        raise KsftSkipEx(f"{end}: VF netdev didn't show up")

    for port in end.devlink_json("port show")["port"].values():
        if port.get("flavour") == "pcivf" and port.get("vfnum") == 0 and \
           port.get("netdev"):
            end.rep = port["netdev"]
    if not end.rep:
        raise KsftSkipEx(f"{end}: VF representor not found")
    ip(f"link set dev {end.rep} up", host=end.host)

    end.netns = f"psptun{os.getpid()}"
    ip(f"netns add {end.netns}", host=end.host)
    # Deleting the netns returns the VF to the init netns
    stack.callback(ip, f"netns del {end.netns}", host=end.host)
    ip(f"link set dev {end.vf} netns {end.netns}", host=end.host)

    outer = cfg.addr_ipver
    mtu = ip(f"link show dev {end.ifname}", json=True, host=end.host)[0]["mtu"]
    vf_mtu = mtu - TUN_OVERHEAD[outer]
    ns = end.netns
    ip(f"link set dev {end.vf} mtu {vf_mtu} up", ns=ns, host=end.host)
    ip("link set dev lo up", ns=ns, host=end.host)
    peer = 1 - end.idx
    for ver, (*addrs, plen) in INNER.items():
        nodad = " nodad" if ver == "6" else ""
        ip(f"addr add {addrs[end.idx]}/{plen} dev {end.vf}{nodad}",
           ns=ns, host=end.host)
        # Everything the VF sends goes into the tunnel, the L2 header is
        # replaced. No ARP / ND through it.
        ip(f"neigh add {addrs[peer]} lladdr {GW_MAC} dev {end.vf} "
           "nud permanent", ns=ns, host=end.host)

    # The tc filters on the uplink and the representor
    for dev_name in (end.ifname, end.rep):
        if cmd(f"tc qdisc add dev {dev_name} clsact", host=end.host,
               fail=False).ret == 0:
            stack.callback(cmd, f"tc qdisc del dev {dev_name} clsact",
                           host=end.host)

    # The PSP device, with all versions enabled
    ifindex = ip(f"link show dev {end.ifname}", json=True,
                 host=end.host)[0]["ifindex"]
    for psp_dev in end.psp("dev-get", {}, dump=True):
        if psp_dev["ifindex"] == ifindex:
            break
    else:
        raise KsftSkipEx(f"{end}: no PSP device on {end.ifname} in switchdev")
    end.psp_dev_id = psp_dev["id"]
    end.versions = psp_dev["psp-versions-cap"]
    if psp_dev["psp-versions-ena"] != end.versions:
        end.psp("dev-set", {"id": end.psp_dev_id,
                            "psp-versions-ena": end.versions})
        stack.callback(end.psp, "dev-set",
                       {"id": end.psp_dev_id,
                        "psp-versions-ena": psp_dev["psp-versions-ena"]})
    ksft_pr(f"{end}: uplink {end.ifname} ({end.pci}), VF {end.vf} "
            f"in {end.netns}, rep {end.rep}, VF MTU {vf_mtu}")


def _wait_outer(cfg):
    """The uplinks went through a mode change, wait for them to pass traffic"""
    ping = "ping -6" if cfg.addr_ipver == "6" else "ping"
    for _ in range(30):
        if cmd(f"{ping} -c 1 -W 1 {cfg.remote_addr}", fail=False).ret == 0:
            return
    raise KsftSkipEx("no connectivity to the remote after switchdev setup")


def _tunnel_setup(cfg, inner, version=0, bad_key_end=None, encap=None):
    """
    Associations and tc rules on both ends. With @bad_key_end, that end
    encrypts with a corrupted key. @encap maps the pref of each encap rule
    to its flower match, where {src} and {dst} are the inner addresses;
    by default one rule takes everything.
    """
    ends = cfg.ends
    encap = encap or {PREF: ""}
    inner_proto = "ipv6" if inner == "6" else "ip"
    addrs = (cfg.addr, cfg.remote_addr)

    rx = [end.rx_spi_alloc(version) for end in ends]
    for end in ends:
        key = dict(rx[1 - end.idx]["rx-key"])
        if end is bad_key_end:
            key["key"] = bytes(b ^ 0xff for b in key["key"])
        tx = end.assoc_add(version, key)

        # Encap: what the VF sends, to the other end
        inner_addrs = INNER[inner]
        for pref, match in encap.items():
            match = match.format(src=inner_addrs[end.idx],
                                 dst=inner_addrs[1 - end.idx])
            cmd(f"tc filter add dev {end.rep} ingress protocol {inner_proto} "
                f"pref {pref} flower skip_sw {match} "
                f"action tunnel_key set src_ip {addrs[end.idx]} "
                f"dst_ip {addrs[1 - end.idx]} dst_port {PSP_PORT} "
                f"action psp encap assoc {tx['id']} mode tunnel "
                f"action mirred egress redirect dev {end.ifname}",
                host=end.host)
            defer(cmd, f"tc filter del dev {end.rep} ingress pref {pref}",
                  host=end.host)

        # Decap: what was decrypted with our Rx SPI, to the VF
        end.decap_match = (f"psp_spi {rx[end.idx]['rx-key']['spi']:#x} "
                           f"psp_ver {version} psp_dev {end.psp_dev_id}")
        _decap_rule(cfg, end, end.decap_match)
        defer(cmd, f"tc filter del dev {end.ifname} ingress pref {PREF}",
              host=end.host)

    for end in ends:
        rules = [(end.rep, pref) for pref in encap] + [(end.ifname, PREF)]
        for dev_name, pref in rules:
            in_hw, _ = end.rule_stats(dev_name, pref)
            ksft_true(in_hw, f"{end}: rule on {dev_name} pref {pref} "
                             "not in hardware")


def _decap_rule(cfg, end, match, op="add"):
    """The decap rule on @end's uplink, taking the PSP packets of @match"""
    outer_proto = "ipv6" if cfg.addr_ipver == "6" else "ip"
    addr = cfg.remote_addr if end.remote else cfg.addr
    cmd(f"tc filter {op} dev {end.ifname} ingress protocol {outer_proto} "
        f"pref {PREF} handle 1 flower skip_sw "
        f"dst_ip {addr} ip_proto udp dst_port {PSP_PORT} {match} "
        f"action psp decap mode tunnel "
        f"action vlan push_eth dst_mac {end.vf_mac} src_mac {GW_MAC} "
        f"action mirred egress redirect dev {end.rep}", host=end.host)


def _ping(end, inner, cnt=PING_CNT, size=None):
    """Ping the other end's VF from @end's VF, return the replies"""
    peer = INNER[inner][1 - end.idx]
    ping = "ping -6" if inner == "6" else "ping"
    size = f"-s {size} -M do " if size else ""
    out = cmd(f"{ping} -c {cnt} -i 0.05 -W 1 {size}{peer}", ns=end.netns,
              host=end.host, fail=False).stdout
    for line in out.splitlines():
        if " received" in line:
            return int(line.split(",")[1].split()[0])
    return 0


def _vf_mtu(end):
    return ip(f"link show dev {end.vf}", json=True, ns=end.netns,
              host=end.host)[0]["mtu"]


def _max_payload(end, inner):
    return _vf_mtu(end) - (40 if inner == "6" else 20) - 8


def _frag_count(size, mtu, inner):
    """Fragments of a UDP datagram with @size bytes of payload"""
    # IPv6 fragments carry a Fragment header
    l3 = 40 + 8 if inner == "6" else 20
    per_frag = (mtu - l3) // 8 * 8
    return -(-(size + 8) // per_frag)


def _udp_send_recv(src, dst, inner, sizes):
    """
    Send datagrams of @sizes from @src's VF to @dst's VF, return the sizes
    of those received
    """
    with bkg(f"python3 -c '{UDP_RECV}' {inner} {UDP_PORT} 5", shell=True,
             ns=dst.netns, host=dst.host, exit_wait=True) as rx:
        wait_port_listen(UDP_PORT, proto="udp", ns=dst.netns, host=dst.host)
        cmd(f"python3 -c '{UDP_SEND}' {inner} {INNER[inner][dst.idx]} "
            f"{UDP_PORT} {' '.join(map(str, sizes))}", shell=True,
            ns=src.netns, host=src.host)
    return [int(n) for n in rx.stdout.split()]


def _inner_variants():
    for inner in ("4", "6"):
        yield KsftNamedVariant(f"inner_v{inner}", inner)


def _version_variants():
    for version in range(4):
        yield KsftNamedVariant(f"v{version}", version)


@ksft_variants(_inner_variants())
def tunnel_ping(cfg, inner):
    """Ping between the VFs through the tunnel, both ways"""
    _tunnel_setup(cfg, inner)

    for end in cfg.ends:
        peer = cfg.ends[1 - end.idx]
        before = (end.stats(), peer.stats())

        ksft_eq(_ping(end, inner), PING_CNT,
                comment=f"replies to {end}'s pings")

        after = (end.stats(), peer.stats())
        for i, which in enumerate((end, peer)):
            for key in ("tx-packets", "rx-packets"):
                ksft_ge(after[i][key] - before[i][key], PING_CNT,
                        comment=f"{which} PSP {key}")
            ksft_eq(after[i]["rx-auth-fail"], before[i]["rx-auth-fail"],
                    comment=f"{which} PSP rx-auth-fail")

    # Each rule saw the pings one way and the replies the other
    for end in cfg.ends:
        for dev_name in (end.rep, end.ifname):
            ksft_ge(end.rule_hits(dev_name, 2 * PING_CNT), 2 * PING_CNT,
                    comment=f"{end}: hits of the rule on {dev_name}")


@ksft_variants(_inner_variants())
def tunnel_mtu(cfg, inner):
    """Full-size packets of the VF MTU go through, one byte more doesn't"""
    _tunnel_setup(cfg, inner)

    end = cfg.ends[0]
    size = _max_payload(end, inner)
    ksft_eq(_ping(end, inner, cnt=5, size=size), 5,
            comment=f"replies to {size} byte pings")


@ksft_variants(_version_variants())
def tunnel_version(cfg, version):
    """Each PSP version both ends support"""
    name = cfg.pspnl.consts["version"].entries_by_val[version].name
    for end in cfg.ends:
        if name not in end.versions:
            raise KsftSkipEx(f"{end}: PSP version {name} not supported")
    _tunnel_setup(cfg, "6", version=version)

    ksft_eq(_ping(cfg.ends[0], "6"), PING_CNT, comment="replies")


def tunnel_decap_match(cfg):
    """Decap only takes the packets of its SPI, PSP version and device"""
    loc, rem = cfg.ends
    _tunnel_setup(cfg, "6")
    ksft_eq(_ping(loc, "6", cnt=5), 5, comment="replies")

    # The replies are decrypted with our SPI, but version 0
    _decap_rule(cfg, loc, loc.decap_match.replace("psp_ver 0", "psp_ver 1"),
                op="replace")
    _, hits = loc.rule_stats(loc.ifname)
    ksft_eq(_ping(loc, "6", cnt=5), 0, comment="replies, wrong psp_ver")
    time.sleep(1.5)
    ksft_eq(loc.rule_stats(loc.ifname)[1], hits,
            comment="hits of the decap rule, wrong psp_ver")

    _decap_rule(cfg, loc, loc.decap_match, op="replace")
    ksft_eq(_ping(loc, "6", cnt=5), 5, comment="replies, right psp_ver")

    # Another PSP device never decrypts what gets to this one's rules
    other = f"psp_dev {loc.psp_dev_id + 1}"
    ret = None
    try:
        _decap_rule(cfg, loc, loc.decap_match.replace(
            f"psp_dev {loc.psp_dev_id}", other), op="replace")
    except CmdExitFailure as e:
        ret = e
    ksft_true(ret, "decap rule for another PSP device not rejected")


def tunnel_bad_key(cfg):
    """Packets encrypted with the wrong key are dropped and counted"""
    loc, rem = cfg.ends
    _tunnel_setup(cfg, "6", bad_key_end=rem)

    before = loc.stats()
    ksft_eq(_ping(loc, "6", cnt=5), 0, comment="replies")
    after = loc.stats()
    ksft_pr("local PSP stats deltas:",
            {k: after[k] - before[k] for k in after if k != "dev-id"})
    ksft_ge(after["rx-auth-fail"] - before["rx-auth-fail"], 5,
            comment="local PSP rx-auth-fail")


@ksft_variants(_inner_variants())
def tunnel_udp_frag(cfg, inner):
    """UDP datagrams over the VF MTU, fragmented by the sender, both ways"""
    _tunnel_setup(cfg, inner)

    for src in cfg.ends:
        dst = cfg.ends[1 - src.idx]
        sizes = [3 * _vf_mtu(src)] * UDP_CNT
        ksft_eq(_udp_send_recv(src, dst, inner, sizes), sizes,
                comment=f"datagrams {src} -> {dst}")


@ksft_variants(_inner_variants())
def tunnel_udp_frag_flow(cfg, inner):
    """
    Per-flow encap rules, as a control plane which authorizes flows would
    install them: a 5-tuple rule for unfragmented packets and, since
    fragments have no ports, a rule on the addresses with ip_flags frag
    for the flow's fragments, the first one included.
    """
    l4 = f"ip_proto udp dst_port {UDP_PORT}"
    try:
        _tunnel_setup(cfg, inner, encap={
            PREF: f"src_ip {{src}} dst_ip {{dst}} {l4} ip_flags nofrag",
            PREF + 10: "src_ip {src} dst_ip {dst} ip_flags frag"})
    except CmdExitFailure as e:
        raise KsftSkipEx("device can't offload the fragment matches") from e

    for src in cfg.ends:
        dst = cfg.ends[1 - src.idx]
        big = 3 * _vf_mtu(src)
        sizes = [100] * UDP_CNT + [big] * UDP_CNT
        ksft_eq(_udp_send_recv(src, dst, inner, sizes), sizes,
                comment=f"datagrams {src} -> {dst}")

        frags = UDP_CNT * _frag_count(big, _vf_mtu(src), inner)
        ksft_eq(src.rule_hits(src.rep, UDP_CNT, PREF), UDP_CNT,
                comment=f"{src}: hits of the 5-tuple rule")
        ksft_eq(src.rule_hits(src.rep, frags, PREF + 10), frags,
                comment=f"{src}: hits of the fragment rule")


def _require_tc_psp_tunnel(cfg):
    for host in (None, cfg.remote):
        out = cmd("tc action add action psp help", host=host, fail=False)
        if "mode" not in out.stdout + out.stderr:
            raise KsftSkipEx("tc does not support psp tunnel mode")


def main() -> None:
    """ Ksft boiler plate main """
    with NetDrvEpEnv(__file__, nsim_test=False) as cfg:
        cfg.require_ipver(cfg.addr_ipver)
        _require_tc_psp_tunnel(cfg)
        cfg.require_cmd("ynl", local=False, remote=True)

        cfg.pspnl = PSPFamily()
        cfg.ends = (End(cfg, 0), End(cfg, 1))
        cfg.ends[0].pspnl = cfg.pspnl
        cfg.ends[1].spec = cfg.remote.deploy(_spec_path())

        with ExitStack() as stack:
            for end in cfg.ends:
                _setup_end(stack, cfg, end)
            _wait_outer(cfg)

            ksft_run([tunnel_ping, tunnel_mtu, tunnel_version,
                      tunnel_decap_match, tunnel_bad_key, tunnel_udp_frag,
                      tunnel_udp_frag_flow],
                     args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
