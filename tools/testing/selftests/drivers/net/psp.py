#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

"""Test suite for PSP capable drivers."""

import errno
import fcntl
import os
import socket
import struct
import termios
import time

from contextlib import contextmanager

from lib.py import defer
from lib.py import ksft_run, ksft_exit, ksft_pr
from lib.py import ksft_true, ksft_eq, ksft_ne, ksft_gt, ksft_ge
from lib.py import ksft_raises
from lib.py import ksft_not_none
from lib.py import ksft_variants, KsftNamedVariant
from lib.py import KsftSkipEx, KsftFailEx, CmdExitFailure
from lib.py import NetDrvEpEnv, NetDrvContEnv
from lib.py import Netlink, NlError, PSPFamily, RtnlFamily
from lib.py import NetNS, NetNSEnter
from lib.py import bkg, rand_port, wait_port_listen
from lib.py import cmd, ip, tc

TCP_ULP = 31
IP_MTU_DISCOVER = 10
IP_PMTUDISC_OMIT = 5
UDP_SEGMENT = 103


def _get_outq(s):
    one = b'\0' * 4
    outq = fcntl.ioctl(s.fileno(), termios.TIOCOUTQ, one)
    return struct.unpack("I", outq)[0]


def _send_with_ack(cfg, msg):
    cfg.comm_sock.send(msg)
    response = cfg.comm_sock.recv(4)
    if response != b'ack\0':
        raise RuntimeError("Unexpected server response", response)


def _remote_read_len(cfg):
    cfg.comm_sock.send(b'read len\0')
    return int(cfg.comm_sock.recv(1024)[:-1].decode('utf-8'))


def _make_clr_conn(cfg, ipver=None):
    _send_with_ack(cfg, b'conn clr\0')
    remote_addr = cfg.remote_addr_v[ipver] if ipver else cfg.remote_addr
    s = socket.create_connection((remote_addr, cfg.comm_port), )
    return s


def _make_psp_conn(cfg, version=0, ipver=None):
    _send_with_ack(cfg, b'conn psp\0' + struct.pack('BB', version, version))
    remote_addr = cfg.remote_addr_v[ipver] if ipver else cfg.remote_addr
    s = socket.create_connection((remote_addr, cfg.comm_port), )
    return s


@contextmanager
def _make_lo_conn():
    # After tx-assoc, the client's egress is dropped, since lo has no
    # psp_dev, so its FIN never reaches the server. Closing the server
    # resets the unaccepted child, and the client accepts the cleartext
    # RST because it hasn't received any PSP traffic yet.
    with socket.create_server(("localhost", 0)) as srv, \
         socket.create_connection(srv.getsockname()[:2]) as s:
        yield s


def _close_conn(cfg, s):
    _send_with_ack(cfg, b'data close\0')
    s.close()


def _close_psp_conn(cfg, s):
    _close_conn(cfg, s)


def _spi_xchg(s, rx):
    s.send(struct.pack('I', rx['spi']) + rx['key'])
    tx = s.recv(4 + len(rx['key']))
    return {
        'spi': struct.unpack('I', tx[:4])[0],
        'key': tx[4:]
    }


def _send_careful(cfg, s, rounds):
    data = b'0123456789' * 200
    for i in range(rounds):
        n = 0
        for _ in range(10): # allow 10 retries
            try:
                n += s.send(data[n:], socket.MSG_DONTWAIT)
                if n == len(data):
                    break
            except BlockingIOError:
                time.sleep(0.05)
        else:
            rlen = _remote_read_len(cfg)
            outq = _get_outq(s)
            report = f'sent: {i * len(data) + n} remote len: {rlen} outq: {outq}'
            raise RuntimeError(report)

    return len(data) * rounds


def _check_data_rx(cfg, exp_len):
    read_len = -1
    for _ in range(30):
        cfg.comm_sock.send(b'read len\0')
        read_len = int(cfg.comm_sock.recv(1024)[:-1].decode('utf-8'))
        if read_len == exp_len:
            break
        time.sleep(0.01)
    ksft_eq(read_len, exp_len)


def _check_data_outq(s, exp_len, force_wait=False):
    outq = 0
    for _ in range(10):
        outq = _get_outq(s)
        if not force_wait and outq == exp_len:
            break
        time.sleep(0.01)
    ksft_eq(outq, exp_len)


def _get_stat(cfg, key):
    return cfg.pspnl.get_stats({'dev-id': cfg.psp_dev_id})[key]


def _get_quiesced_stat(cfg, key, timeout=10):
    """
    Like _get_stat(), but wait till the value stops changing. Note
    that some devices refresh flow counters periodically, e.g. once
    per second with mlx5.
    """
    val = _get_stat(cfg, key)
    end = time.monotonic() + timeout
    while True:
        time.sleep(1.5)
        new = _get_stat(cfg, key)
        if new == val:
            return val
        val = new
        if time.monotonic() >= end:
            ksft_pr(f"{key} still changing after {timeout}s: {val}")
            return val


def _remote_count(cfg, proto, match):
    """
    Count, and drop, the @proto packets matching flower @match which reach
    the remote, with a software filter on its ingress (offloaded filter
    counters are refreshed periodically). Dropping keeps such packets away
    from the remote's stack. Returns a function reading the count, or None
    if the filter can't be installed.
    """
    flt = (f"dev {cfg.remote_ifname} ingress protocol {proto} pref 1 "
           f"handle 0x5053 flower")
    try:
        qdiscs = tc(f"qdisc show dev {cfg.remote_ifname}", json=True,
                    host=cfg.remote)
        # An ingress qdisc takes the filter as well as clsact
        if not any(q['kind'] in ('clsact', 'ingress') for q in qdiscs):
            tc(f"qdisc add dev {cfg.remote_ifname} clsact", host=cfg.remote)
            defer(tc, f"qdisc del dev {cfg.remote_ifname} clsact",
                  host=cfg.remote)
        tc(f"filter add {flt} skip_hw {match} action drop", host=cfg.remote)
    except CmdExitFailure as e:
        ksft_pr(f"Can't install a filter on the remote: {e}")
        return None
    defer(tc, f"filter del {flt}", host=cfg.remote)

    def count():
        filters = tc(f"-s filter get {flt}", json=True, host=cfg.remote)
        for f in filters:
            for act in f.get("options", {}).get("actions", []):
                return act["stats"]["packets"]
        raise KsftFailEx("no action on the remote filter")
    return count

#
# Test case boiler plate
#

def _init_psp_dev(cfg, use_psp_ifindex=False):
    if not hasattr(cfg, 'psp_dev_id'):
        # Figure out which local device we are testing against
        # For NetDrvContEnv: use psp_ifindex instead of ifindex
        target_ifindex = cfg.psp_ifindex if use_psp_ifindex else cfg.ifindex
        for dev in cfg.pspnl.dev_get({}, dump=True):
            if dev['ifindex'] == target_ifindex:
                cfg.psp_info = dev
                cfg.psp_dev_id = cfg.psp_info['id']
                break
        else:
            raise KsftSkipEx("No PSP devices found")

    # Enable PSP if necessary
    cap = cfg.psp_info['psp-versions-cap']
    ena = cfg.psp_info['psp-versions-ena']
    if cap != ena:
        cfg.pspnl.dev_set({'id': cfg.psp_dev_id, 'psp-versions-ena': cap})
        defer(cfg.pspnl.dev_set, {'id': cfg.psp_dev_id,
                                  'psp-versions-ena': ena })

#
# Test cases
#

def dev_list_devices(cfg):
    """ Dump all devices """
    _init_psp_dev(cfg)

    devices = cfg.pspnl.dev_get({}, dump=True)

    found = False
    for dev in devices:
        found |= dev['id'] == cfg.psp_dev_id
    ksft_true(found)


def dev_get_device(cfg):
    """ Get the device we intend to use """
    _init_psp_dev(cfg)

    dev = cfg.pspnl.dev_get({'id': cfg.psp_dev_id})
    ksft_eq(dev['id'], cfg.psp_dev_id)


def dev_get_device_bad(cfg):
    """ Test getting device which doesn't exist """
    raised = False
    try:
        cfg.pspnl.dev_get({'id': 1234567})
    except NlError as e:
        ksft_eq(e.nl_msg.error, -errno.ENODEV)
        raised = True
    ksft_true(raised)


def dev_rotate(cfg):
    """ Test key rotation """
    _init_psp_dev(cfg)

    prev_rotations = _get_stat(cfg, 'key-rotations')

    rot = cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
    ksft_eq(rot['id'], cfg.psp_dev_id)
    rot = cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
    ksft_eq(rot['id'], cfg.psp_dev_id)

    cur_rotations = _get_stat(cfg, 'key-rotations')
    ksft_eq(cur_rotations, prev_rotations + 2)


def dev_rotate_spi(cfg):
    """ Test key rotation and SPI check """
    _init_psp_dev(cfg)

    top_a = top_b = 0
    with _make_lo_conn() as s:
        assoc_a = cfg.pspnl.rx_assoc({"version": 0,
                                     "dev-id": cfg.psp_dev_id,
                                     "sock-fd": s.fileno()})
        top_a = assoc_a['rx-key']['spi'] >> 31
    rot = cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
    with _make_lo_conn() as s:
        ksft_eq(rot['id'], cfg.psp_dev_id)
        assoc_b = cfg.pspnl.rx_assoc({"version": 0,
                                    "dev-id": cfg.psp_dev_id,
                                    "sock-fd": s.fileno()})
        top_b = assoc_b['rx-key']['spi'] >> 31
    ksft_ne(top_a, top_b)


def assoc_basic(cfg):
    """ Test creating associations """
    _init_psp_dev(cfg)

    with _make_lo_conn() as s:
        assoc = cfg.pspnl.rx_assoc({"version": 0,
                                  "dev-id": cfg.psp_dev_id,
                                  "sock-fd": s.fileno()})
        ksft_eq(assoc['dev-id'], cfg.psp_dev_id)
        ksft_gt(assoc['rx-key']['spi'], 0)
        ksft_eq(len(assoc['rx-key']['key']), 16)

        assoc = cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                  "version": 0,
                                  "tx-key": assoc['rx-key'],
                                  "sock-fd": s.fileno()})
        ksft_eq(len(assoc), 0)


def assoc_bad_dev(cfg):
    """ Test creating associations with bad device ID """
    _init_psp_dev(cfg)

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        with ksft_raises(NlError) as cm:
            cfg.pspnl.rx_assoc({"version": 0,
                              "dev-id": cfg.psp_dev_id + 1234567,
                              "sock-fd": s.fileno()})
        ksft_eq(cm.exception.nl_msg.error, -errno.ENODEV)


def assoc_sk_only_conn(cfg):
    """ Test creating associations based on socket """
    _init_psp_dev(cfg)

    with _make_clr_conn(cfg) as s:
        assoc = cfg.pspnl.rx_assoc({"version": 0,
                                  "sock-fd": s.fileno()})
        ksft_eq(assoc['dev-id'], cfg.psp_dev_id)
        cfg.pspnl.tx_assoc({"version": 0,
                          "tx-key": assoc['rx-key'],
                          "sock-fd": s.fileno()})
        _close_conn(cfg, s)


def assoc_sk_only_mismatch(cfg):
    """ Test creating associations based on socket (dev mismatch) """
    _init_psp_dev(cfg)

    with _make_clr_conn(cfg) as s:
        with ksft_raises(NlError) as cm:
            cfg.pspnl.rx_assoc({"version": 0,
                              "dev-id": cfg.psp_dev_id + 1234567,
                              "sock-fd": s.fileno()})
        the_exception = cm.exception
        ksft_eq(the_exception.nl_msg.extack['bad-attr'], ".dev-id")
        ksft_eq(the_exception.nl_msg.error, -errno.EINVAL)
        _close_conn(cfg, s)


def assoc_sk_only_mismatch_tx(cfg):
    """ Test creating associations based on socket (dev mismatch) """
    _init_psp_dev(cfg)

    with _make_clr_conn(cfg) as s:
        with ksft_raises(NlError) as cm:
            assoc = cfg.pspnl.rx_assoc({"version": 0,
                                      "sock-fd": s.fileno()})
            cfg.pspnl.tx_assoc({"version": 0,
                              "tx-key": assoc['rx-key'],
                              "dev-id": cfg.psp_dev_id + 1234567,
                              "sock-fd": s.fileno()})
        the_exception = cm.exception
        ksft_eq(the_exception.nl_msg.extack['bad-attr'], ".dev-id")
        ksft_eq(the_exception.nl_msg.error, -errno.EINVAL)
        _close_conn(cfg, s)


def assoc_sk_only_unconn(cfg):
    """ Test creating associations based on socket (unconnected, should fail) """
    _init_psp_dev(cfg)

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        with ksft_raises(NlError) as cm:
            cfg.pspnl.rx_assoc({"version": 0,
                              "sock-fd": s.fileno()})
        the_exception = cm.exception
        ksft_eq(the_exception.nl_msg.extack['miss-type'], "dev-id")
        ksft_eq(the_exception.nl_msg.error, -errno.EINVAL)


def assoc_rx_unconnected(cfg):
    """ Test that an Rx assoc is rejected on an unconnected socket """
    _init_psp_dev(cfg)

    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        with ksft_raises(NlError) as cm:
            cfg.pspnl.rx_assoc({"version": 0,
                                "dev-id": cfg.psp_dev_id,
                                "sock-fd": s.fileno()})
        ksft_eq(cm.exception.nl_msg.error, -errno.ENOTCONN)
        ksft_eq(cm.exception.nl_msg.extack['bad-attr'], ".sock-fd")


def assoc_rx_listener(cfg):
    """ Test that an Rx assoc is rejected on a listening socket """
    _init_psp_dev(cfg)

    with socket.create_server(("localhost", 0)) as s:
        with ksft_raises(NlError) as cm:
            cfg.pspnl.rx_assoc({"version": 0,
                                "dev-id": cfg.psp_dev_id,
                                "sock-fd": s.fileno()})
        ksft_eq(cm.exception.nl_msg.error, -errno.ENOTCONN)
        ksft_eq(cm.exception.nl_msg.extack['bad-attr'], ".sock-fd")


def assoc_version_mismatch(cfg):
    """ Test creating associations where Rx and Tx PSP versions do not match """
    _init_psp_dev(cfg)

    versions = list(cfg.psp_info['psp-versions-cap'])
    if len(versions) < 2:
        raise KsftSkipEx("Not enough PSP versions supported by the device for the test")

    # Translate versions to integers
    versions = [cfg.pspnl.consts["version"].entries[v].value for v in versions]

    with _make_lo_conn() as s:
        rx = cfg.pspnl.rx_assoc({"version": versions[0],
                                 "dev-id": cfg.psp_dev_id,
                                 "sock-fd": s.fileno()})

        for version in versions[1:]:
            with ksft_raises(NlError) as cm:
                cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                    "version": version,
                                    "tx-key": rx['rx-key'],
                                    "sock-fd": s.fileno()})
            the_exception = cm.exception
            ksft_eq(the_exception.nl_msg.error, -errno.EINVAL)


def _require_tls_ulp():
    with socket.create_server(("localhost", 0)) as srv, \
         socket.create_connection(srv.getsockname()) as s:
        try:
            s.setsockopt(socket.SOL_TCP, TCP_ULP, b"tls")
        except OSError as exc:
            raise KsftSkipEx("kTLS not available") from exc


def assoc_psp_ulp_exclusive(cfg):
    """ Test that a TCP ULP cannot be attached to a PSP socket """
    _init_psp_dev(cfg)
    _require_tls_ulp()

    with _make_clr_conn(cfg) as s:
        try:
            cfg.pspnl.rx_assoc({"version": 0,
                                "dev-id": cfg.psp_dev_id,
                                "sock-fd": s.fileno()})
            with ksft_raises(OSError) as cm:
                s.setsockopt(socket.SOL_TCP, TCP_ULP, b"tls")
            ksft_eq(cm.exception.errno, errno.EINVAL)
        finally:
            _close_conn(cfg, s)


def assoc_ulp_psp_exclusive(cfg):
    """ Test that a PSP assoc cannot be added to a socket with a TCP ULP """
    _init_psp_dev(cfg)
    _require_tls_ulp()

    with _make_clr_conn(cfg) as s:
        try:
            s.setsockopt(socket.SOL_TCP, TCP_ULP, b"tls")
            with ksft_raises(NlError) as cm:
                cfg.pspnl.rx_assoc({"version": 0,
                                    "dev-id": cfg.psp_dev_id,
                                    "sock-fd": s.fileno()})
            ksft_eq(cm.exception.nl_msg.error, -errno.EINVAL)
            ksft_eq(cm.exception.nl_msg.extack['bad-attr'], ".sock-fd")
        finally:
            _close_conn(cfg, s)


def assoc_twice(cfg):
    """ Test reusing Tx assoc for two sockets """
    _init_psp_dev(cfg)

    def rx_assoc_check(s):
        assoc = cfg.pspnl.rx_assoc({"version": 0,
                                  "dev-id": cfg.psp_dev_id,
                                  "sock-fd": s.fileno()})
        ksft_eq(assoc['dev-id'], cfg.psp_dev_id)
        ksft_gt(assoc['rx-key']['spi'], 0)
        ksft_eq(len(assoc['rx-key']['key']), 16)

        return assoc

    with _make_lo_conn() as s:
        assoc = rx_assoc_check(s)
        tx = cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                               "version": 0,
                               "tx-key": assoc['rx-key'],
                               "sock-fd": s.fileno()})
        ksft_eq(len(tx), 0)

        # Use the same Tx assoc second time
        with _make_lo_conn() as s2:
            rx_assoc_check(s2)
            tx = cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                                   "version": 0,
                                   "tx-key": assoc['rx-key'],
                                   "sock-fd": s2.fileno()})
            ksft_eq(len(tx), 0)


def _data_basic_send(cfg, version, ipver):
    """ Test basic data send """
    _init_psp_dev(cfg)

    # Version 0 is required by spec, don't let it skip
    if version:
        name = cfg.pspnl.consts["version"].entries_by_val[version].name
        if name not in cfg.psp_info['psp-versions-cap']:
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
                with ksft_raises(NlError) as cm:
                    cfg.pspnl.rx_assoc({"version": version,
                                        "dev-id": cfg.psp_dev_id,
                                        "sock-fd": s.fileno()})
                ksft_eq(cm.exception.nl_msg.error, -errno.EOPNOTSUPP)
            raise KsftSkipEx("PSP version not supported", name)

    s = _make_psp_conn(cfg, version, ipver)

    rx_assoc = cfg.pspnl.rx_assoc({"version": version,
                                   "dev-id": cfg.psp_dev_id,
                                   "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    tx = _spi_xchg(s, rx)

    cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                        "version": version,
                        "tx-key": tx,
                        "sock-fd": s.fileno()})

    data_len = _send_careful(cfg, s, 100)
    _check_data_rx(cfg, data_len)
    _close_psp_conn(cfg, s)


def __bad_xfer_do(cfg, s, tx, version='hdr0-aes-gcm-128'):
    # Make sure we accept the ACK for the SPI before we seal with the bad assoc
    _check_data_outq(s, 0)

    cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                        "version": version,
                        "tx-key": tx,
                        "sock-fd": s.fileno()})

    data_len = _send_careful(cfg, s, 20)
    _check_data_outq(s, data_len, force_wait=True)
    _check_data_rx(cfg, 0)
    _close_psp_conn(cfg, s)


def data_send_bad_key(cfg):
    """ Test send data with bad key """
    _init_psp_dev(cfg)

    s = _make_psp_conn(cfg)

    rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                   "dev-id": cfg.psp_dev_id,
                                   "sock-fd": s.fileno()})
    rx = rx_assoc['rx-key']
    tx = _spi_xchg(s, rx)
    tx['key'] = (tx['key'][0] ^ 0xff).to_bytes(1, 'little') + tx['key'][1:]
    __bad_xfer_do(cfg, s, tx)


def data_send_disconnect(cfg):
    """ Test socket close after sending data """
    _init_psp_dev(cfg)

    with _make_psp_conn(cfg) as s:
        assoc = cfg.pspnl.rx_assoc({"version": 0,
                                  "sock-fd": s.fileno()})
        tx = _spi_xchg(s, assoc['rx-key'])
        cfg.pspnl.tx_assoc({"version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        data_len = _send_careful(cfg, s, 100)
        _check_data_rx(cfg, data_len)

        s.shutdown(socket.SHUT_RDWR)
        s.close()


def _data_mss_adjust(cfg, ipver):
    _init_psp_dev(cfg)

    # First figure out what the MSS would be without any adjustments
    s = _make_clr_conn(cfg, ipver)
    s.send(b"0123456789abcdef" * 1024)
    _check_data_rx(cfg, 16 * 1024)
    mss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    _close_conn(cfg, s)

    s = _make_psp_conn(cfg, 0, ipver)
    try:
        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                     "dev-id": cfg.psp_dev_id,
                                     "sock-fd": s.fileno()})
        rx = rx_assoc['rx-key']
        tx = _spi_xchg(s, rx)

        rxmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        ksft_eq(mss, rxmss)

        cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        txmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        ksft_eq(mss, txmss + 40)

        data_len = _send_careful(cfg, s, 100)
        _check_data_rx(cfg, data_len)
        _check_data_outq(s, 0)

        txmss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        ksft_eq(mss, txmss + 40)
    finally:
        _close_psp_conn(cfg, s)


def data_stale_key(cfg):
    """ Test send on a double-rotated key """
    _init_psp_dev(cfg)

    prev_stale = _get_stat(cfg, 'stale-events')
    s = _make_psp_conn(cfg)
    try:
        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                     "dev-id": cfg.psp_dev_id,
                                     "sock-fd": s.fileno()})
        rx = rx_assoc['rx-key']
        tx = _spi_xchg(s, rx)

        cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                          "version": 0,
                          "tx-key": tx,
                          "sock-fd": s.fileno()})

        data_len = _send_careful(cfg, s, 100)
        _check_data_rx(cfg, data_len)
        _check_data_outq(s, 0)

        cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
        cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})

        cur_stale = _get_stat(cfg, 'stale-events')
        ksft_gt(cur_stale, prev_stale)

        s.send(b'0123456789' * 200)
        _check_data_outq(s, 2000, force_wait=True)
    finally:
        _close_psp_conn(cfg, s)


def __nsim_psp_rereg(cfg):
    # The PSP dev ID will change, remember what was there before
    before = {x['id'] for x in cfg.pspnl.dev_get({}, dump=True)}

    cfg._ns.nsims[0].dfs_write('psp_rereg', '1')

    after = {x['id'] for x in cfg.pspnl.dev_get({}, dump=True)}

    new_devs = list(after - before)
    ksft_eq(len(new_devs), 1)
    cfg.psp_dev_id = list(after - before)[0]


def removal_device_rx(cfg):
    """ Test removing a netdev / PSD with active Rx assoc """

    # We could technically devlink reload real devices, too
    # but that kills the control socket. So test this on
    # netdevsim only for now
    cfg.require_nsim()

    s = _make_clr_conn(cfg)
    try:
        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                       "dev-id": cfg.psp_dev_id,
                                       "sock-fd": s.fileno()})
        ksft_not_none(rx_assoc)

        __nsim_psp_rereg(cfg)
    finally:
        _close_conn(cfg, s)


def removal_device_bi(cfg):
    """ Test removing a netdev / PSD with active Rx/Tx assoc """

    # We could technically devlink reload real devices, too
    # but that kills the control socket. So test this on
    # netdevsim only for now
    cfg.require_nsim()

    s = _make_clr_conn(cfg)
    try:
        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                       "dev-id": cfg.psp_dev_id,
                                       "sock-fd": s.fileno()})
        cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                            "version": 0,
                            "tx-key": rx_assoc['rx-key'],
                            "sock-fd": s.fileno()})
        __nsim_psp_rereg(cfg)
    finally:
        _close_conn(cfg, s)


def _ipv6_exthdr_variants():
    padn = bytes([0, 0, 1, 4, 0, 0, 0, 0])  # one PadN option

    def srh(peer):
        """ segment routing header, with @peer as its only segment """
        return (bytes([0, 2, 4, 0, 0, 0, 0, 0]) +
                socket.inet_pton(socket.AF_INET6, peer))

    yield KsftNamedVariant("dstopts", socket.IPV6_DSTOPTS, lambda peer: padn)
    yield KsftNamedVariant("hopopts", socket.IPV6_HOPOPTS, lambda peer: padn)
    yield KsftNamedVariant("rthdr", socket.IPV6_RTHDR, srh)


def _src_addr(dst):
    """ The source address the kernel picks for @dst """
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as u:
        u.connect((dst, 9))
        return u.getsockname()[0]


@ksft_variants(_ipv6_exthdr_variants())
def data_send_ipv6_exthdr(cfg, opt, val):
    """ Test that PSP drops IPv6 packets with an extension header """
    cfg.require_ipver("6")
    _init_psp_dev(cfg)

    # Packets which were encapsulated but malformed or left unencrypted
    # reach the remote as UDP. Set up the count before connecting, so a
    # skip doesn't leave the responder mid key exchange.
    peer = cfg.remote_addr_v["6"]
    remote_udp = _remote_count(cfg, "ipv6", f"src_ip {_src_addr(peer)} "
                               f"dst_ip {peer} ip_proto udp")
    if not remote_udp:
        raise KsftSkipEx("can't count UDP on the remote")

    s = _make_psp_conn(cfg, 0, "6")
    try:
        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                       "dev-id": cfg.psp_dev_id,
                                       "sock-fd": s.fileno()})
        tx = _spi_xchg(s, rx_assoc['rx-key'])
        cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                            "version": 0,
                            "tx-key": tx,
                            "sock-fd": s.fileno()})
        _check_data_outq(s, 0)

        def wait_outq_empty():
            for _ in range(100):
                if _get_outq(s) == 0:
                    break
                time.sleep(0.5)
            _check_data_outq(s, 0)

        # 1. No option: sent, counted, and received
        tx_pkts = _get_quiesced_stat(cfg, 'tx-packets')
        total = _send_careful(cfg, s, 20)
        wait_outq_empty()
        ksft_gt(_get_quiesced_stat(cfg, 'tx-packets'), tx_pkts)
        _check_data_rx(cfg, total)

        # 2. With the option: dropped, not counted, and nothing reaches the
        # peer. The data stays queued.
        s.setsockopt(socket.IPPROTO_IPV6, opt, val(peer))
        tx_pkts = _get_quiesced_stat(cfg, 'tx-packets')
        udp = remote_udp()
        queued = _send_careful(cfg, s, 20)
        _check_data_outq(s, queued, force_wait=True)
        ksft_eq(_get_quiesced_stat(cfg, 'tx-packets'), tx_pkts)
        ksft_eq(remote_udp(), udp, comment="UDP at the remote")
        _check_data_rx(cfg, total)
        total += queued

        # 3. Option removed: the queued data, then new data, sent and
        # received
        tx_pkts = _get_quiesced_stat(cfg, 'tx-packets')
        s.setsockopt(socket.IPPROTO_IPV6, opt, b'')
        wait_outq_empty()
        total += _send_careful(cfg, s, 20)
        wait_outq_empty()
        ksft_gt(_get_quiesced_stat(cfg, 'tx-packets'), tx_pkts)
        _check_data_rx(cfg, total)
    finally:
        # With the option, the queued data, the FIN and the ACKs would be
        # dropped, leaving an orphan holding the association
        s.setsockopt(socket.IPPROTO_IPV6, opt, b'')
        _close_psp_conn(cfg, s)


def _ipv4_snmp(key):
    """ An Ip: counter of this netns, from /proc/net/snmp """
    with open("/proc/net/snmp", encoding="utf-8") as f:
        ip_lines = [line.split() for line in f if line.startswith("Ip:")]
    return int(ip_lines[1][ip_lines[0].index(key)])


def _ipv4_route_mtu(dst, mtu, host=None):
    """ Add a route to @dst with @mtu, keeping the device and source of
    the current one, which must be on-link. Returns the defer removing it.
    """
    route = ip(f"-4 route get {dst}", json=True, host=host)[0]
    if route.get("gateway"):
        raise KsftSkipEx(f"{dst} isn't on-link")
    try:
        ip(f"route add {dst}/32 dev {route['dev']} src {route['prefsrc']} "
           f"mtu {mtu}", host=host)
    except CmdExitFailure as e:
        raise KsftSkipEx(f"can't set the route mtu to {dst}: {e}") from e
    return defer(ip, f"route del {dst}/32 dev {route['dev']}", host=host)


def data_send_ipv4_frags(cfg):
    """ Test that IPv4 packets of a PSP TCP socket aren't fragmented """
    cfg.require_ipver("4")
    _init_psp_dev(cfg)

    # Fragments which get out reach the remote. Set up the count before
    # connecting, so a skip doesn't leave the responder mid key exchange.
    # The socket's source is the one the kernel picks, which may not be
    # LOCAL_V4, and the fragments would leave through the route's device
    rem = cfg.remote_addr_v["4"]
    route = ip(f"-4 route get {rem}", json=True)[0]
    if route["dev"] != cfg.ifname:
        raise KsftSkipEx(f"{rem} isn't routed through {cfg.ifname}")
    loc = route["prefsrc"]
    remote_frags = _remote_count(cfg, "ip",
                                 f"src_ip {loc} dst_ip {rem} ip_flags frag")
    if not remote_frags:
        raise KsftSkipEx("can't count fragments on the remote")

    # TCP sizes its segments from the route MTU. With IP_PMTUDISC_OMIT, IP
    # fragments them to the device MTU. Set a route MTU above the device
    # MTU on both ends, since the peer's MSS limits ours too. While both
    # are in place, a new ssh connection to the remote over these addresses
    # can stall, so add the local one last, and remove it first.
    mtu = min(2 * max(cfg.dev['mtu'], cfg.remote_dev['mtu']), 65535)
    _ipv4_route_mtu(loc, mtu, host=cfg.remote)
    local_route = _ipv4_route_mtu(rem, mtu)

    # With MTU probing on, TCP caps the MSS at the probing base, whatever
    # the route MTU
    probing_path = "/proc/sys/net/ipv4/tcp_mtu_probing"
    with open(probing_path, encoding="utf-8") as fp:
        probing = fp.read().strip()
    if int(probing) > 1:
        def set_probing(val):
            with open(probing_path, "w", encoding="utf-8") as fp:
                fp.write(val)
        set_probing("0")
        defer(set_probing, probing)

    s = _make_psp_conn(cfg, 0, "4")
    try:
        rx_assoc = cfg.pspnl.rx_assoc({"version": 0,
                                       "dev-id": cfg.psp_dev_id,
                                       "sock-fd": s.fileno()})
        tx = _spi_xchg(s, rx_assoc['rx-key'])
        cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                            "version": 0,
                            "tx-key": tx,
                            "sock-fd": s.fileno()})
        s.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_OMIT)
        mss = s.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        if mss + 40 <= cfg.dev['mtu']:
            raise KsftSkipEx(f"mss {mss} needs no fragmenting")

        fails = _ipv4_snmp("FragFails")
        # The packets are dropped, so the send may not complete (with a
        # jumbo device MTU, the socket buffer can take all of it)
        s.settimeout(3)
        try:
            s.sendall(b'f' * 200000)
        except socket.timeout:
            pass
        fails = _ipv4_snmp("FragFails") - fails

        # Before the next ssh to the remote, see above
        local_route.exec()

        # Fragments would go out unencrypted: the packets must be dropped
        # instead of fragmented. FragFails is per netns, so it only
        # confirms the drop: the remote count is what decides.
        ksft_eq(remote_frags(), 0, comment="fragments reached the remote")
        ksft_gt(fails, 0, comment="packets dropped instead of fragmented")
    finally:
        _close_psp_conn(cfg, s)


def _get_psp_ver_ip_variants():
    for ver in range(4):
        for ipv in ("4", "6"):
            yield KsftNamedVariant(f"v{ver}_ip{ipv}", ver, ipv)


def _get_ip_variants():
    for ipv in ("4", "6"):
        yield KsftNamedVariant(f"ip{ipv}", ipv)


@ksft_variants(_get_psp_ver_ip_variants())
def data_basic_send(cfg, version, ipver):
    """Test basic PSP data send."""
    cfg.require_ipver(ipver)
    _data_basic_send(cfg, version, ipver)


@ksft_variants(_get_ip_variants())
def data_mss_adjust(cfg, ipver):
    """Test MSS adjustment with PSP."""
    cfg.require_ipver(ipver)
    _data_mss_adjust(cfg, ipver)


#
# Socket-less associations and the tc psp action
#

def _assoc_del(cfg, assoc_id):
    """ Delete a socket-less assoc, unless the test already did """
    try:
        cfg.pspnl.assoc_del({"id": assoc_id})
    except NlError as e:
        if e.nl_msg.error != -errno.ENOENT:
            raise


def _sockless_assocs(cfg, version=0):
    """ Allocate an Rx SPI and add a Tx assoc with its key """
    rx = cfg.pspnl.rx_spi_alloc({"dev-id": cfg.psp_dev_id,
                                 "version": version})
    defer(_assoc_del, cfg, rx['id'])
    tx = cfg.pspnl.assoc_add({"dev-id": cfg.psp_dev_id,
                              "version": version,
                              "tx-key": rx['rx-key']})
    defer(_assoc_del, cfg, tx['id'])
    return rx, tx


def _require_tc_psp(cfg):
    if not hasattr(cfg, 'tc_psp'):
        # tc exits with an error either way, look at what it says. The
        # tests need both the psp action and the flower psp keys.
        try:
            act = cmd("tc action add action psp help", fail=False)
            flt = cmd("tc filter add dev lo ingress flower help",
                      fail=False)
        except FileNotFoundError:
            cfg.tc_psp = False
        else:
            cfg.tc_psp = ("psp encap" in act.stdout + act.stderr and
                          "psp_spi" in flt.stdout + flt.stderr)
    if not cfg.tc_psp:
        raise KsftSkipEx("tc does not support the psp action and matches")


def _require_psp_version(cfg, version):
    name = cfg.pspnl.consts["version"].entries_by_val[version].name
    if name not in cfg.psp_info['psp-versions-cap']:
        raise KsftSkipEx("PSP version not supported", name)


def _tc_proto(ipver):
    return "ip" if ipver == "4" else "ipv6"


def _tc_clsact(ifname, host=None):
    """ Add clsact to @ifname, unless it has one already: the env or the
    host may use it too, so only remove it if it was added here
    """
    qdiscs = tc(f"qdisc show dev {ifname}", json=True, host=host)
    if any(q['kind'] == 'clsact' for q in qdiscs):
        return
    tc(f"qdisc add dev {ifname} clsact", host=host)
    defer(tc, f"qdisc del dev {ifname} clsact", host=host)


def _make_tc_conn(cfg, version, ipver):
    """ Connect a plain socket to a PSP socket of the responder """
    _send_with_ack(cfg, b'conn psp\0' + struct.pack('BB', version, version))
    family = socket.AF_INET if ipver == "4" else socket.AF_INET6
    s = socket.socket(family, socket.SOCK_STREAM)
    # The stack doesn't know tc will add PSP headers (40 bytes), leave room
    # for them. TCP takes its options off the MSS.
    mtu = ip(f"link show dev {cfg.ifname}", json=True)[0]['mtu']
    iph = 20 if ipver == "4" else 40
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG,
                 mtu - 40 - iph - 20)
    s.connect((cfg.remote_addr_v[ipver], cfg.comm_port))
    defer(_tc_conn_close, cfg, s)
    return s


def _tc_conn_close(cfg, s):
    """ Close a test's connection, unless the test got to do it """
    if s.fileno() != -1:
        _close_psp_conn(cfg, s)


def _tc_psp_conn(cfg, version, ipver, decap=True):
    """
    Connect a plain socket to a PSP socket of the responder, and give that
    flow PSP encap using socket-less assocs and tc: decap what was decrypted
    with its Rx SPI, version and device on ingress, encap its packets on
    egress, which the device encrypts. Returns the socket and the assocs.
    """
    proto = _tc_proto(ipver)

    # The Rx SPI and the decap rule first: once connected, the responder
    # waits for our key, and an error in between would leave the comm
    # channel out of step
    rx = cfg.pspnl.rx_spi_alloc({"dev-id": cfg.psp_dev_id,
                                 "version": version})
    defer(_assoc_del, cfg, rx['id'])

    _tc_clsact(cfg.ifname)
    # The responder starts sending with our SPI as soon as it has our key
    if decap:
        tc(f"filter add dev {cfg.ifname} ingress pref 10 handle 1 "
           f"protocol {proto} flower psp_spi {rx['rx-key']['spi']:#x} "
           f"psp_ver {version} psp_dev {cfg.psp_dev_id} action psp decap")
        defer(tc, f"filter del dev {cfg.ifname} ingress pref 10 handle 1 "
              f"protocol {proto} flower")

    s = _make_tc_conn(cfg, version, ipver)
    tx_key = _spi_xchg(s, rx['rx-key'])
    tx = cfg.pspnl.assoc_add({"dev-id": cfg.psp_dev_id,
                              "version": version,
                              "tx-key": tx_key})
    defer(_assoc_del, cfg, tx['id'])

    # Make sure the SPI exchange got through in clear text
    _check_data_outq(s, 0)

    # The comm socket goes to the same port, match on ours
    sport = s.getsockname()[1]
    tc(f"filter add dev {cfg.ifname} egress pref 10 handle 1 "
       f"protocol {proto} flower ip_proto tcp src_port {sport} "
       f"action psp encap assoc {tx['id']}")
    defer(tc, f"filter del dev {cfg.ifname} egress pref 10 handle 1 "
          f"protocol {proto} flower")

    return s, rx, tx


def _tc_action_stats(cfg, direction):
    """ Stats of the psp action of the pref 10 filter """
    filters = tc(f"-s filter show dev {cfg.ifname} {direction} pref 10",
                 json=True)
    for flt in filters:
        for act in flt.get("options", {}).get("actions", []):
            if act["kind"] == "psp":
                return act["stats"]
    raise KsftFailEx(f"no psp action on {direction}")


def _wait_data_outq(s, exp_len, timeout=5):
    """ Like _check_data_outq() but leave time for retransmits """
    outq = 0
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        outq = _get_outq(s)
        if outq == exp_len:
            break
        time.sleep(0.05)
    ksft_eq(outq, exp_len)


def assoc_sockless_basic(cfg):
    """ Test socket-less associations """
    _init_psp_dev(cfg)

    rx, tx = _sockless_assocs(cfg)
    ksft_eq(rx['dev-id'], cfg.psp_dev_id)
    ksft_gt(rx['rx-key']['spi'], 0)
    ksft_eq(len(rx['rx-key']['key']), 16)
    ksft_eq(tx['dev-id'], cfg.psp_dev_id)
    ksft_ne(tx['id'], rx['id'])

    # Only the SPI is ever reported, never the key
    version = cfg.pspnl.consts["version"].entries_by_val[0].name
    spi = {'spi': rx['rx-key']['spi']}
    assoc = cfg.pspnl.assoc_get({"id": rx['id']})
    ksft_eq(assoc['dev-id'], cfg.psp_dev_id)
    ksft_eq(assoc['version'], version)
    ksft_eq(assoc['rx-key'], spi)
    ksft_true('tx-key' not in assoc)
    assoc = cfg.pspnl.assoc_get({"id": tx['id']})
    ksft_eq(assoc['dev-id'], cfg.psp_dev_id)
    ksft_eq(assoc['version'], version)
    ksft_eq(assoc['tx-key'], spi)
    ksft_true('rx-key' not in assoc)

    ids = [x['id'] for x in cfg.pspnl.assoc_get({}, dump=True)]
    ksft_true(rx['id'] in ids)
    ksft_true(tx['id'] in ids)

    for assoc_id in (rx['id'], tx['id']):
        cfg.pspnl.assoc_del({"id": assoc_id})
        with ksft_raises(NlError) as cm:
            cfg.pspnl.assoc_get({"id": assoc_id})
        ksft_eq(cm.exception.nl_msg.error, -errno.ENOENT)
        with ksft_raises(NlError) as cm:
            cfg.pspnl.assoc_del({"id": assoc_id})
        ksft_eq(cm.exception.nl_msg.error, -errno.ENOENT)


def assoc_sockless_stale(cfg):
    """ Test key rotation marks socket-less Rx assocs stale """
    _init_psp_dev(cfg)

    rx, tx = _sockless_assocs(cfg)
    for assoc_id in (rx['id'], tx['id']):
        ksft_true('stale' not in cfg.pspnl.assoc_get({"id": assoc_id}))
    # The second rotation retires the device key they were created under
    for i in range(2):
        cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})
        stale = 'stale' in cfg.pspnl.assoc_get({"id": rx['id']})
        ksft_eq(stale, i == 1, comment=f"rotation {i + 1}")
    # A Tx assoc holds the peer's key, which the device key rotation
    # doesn't affect
    ksft_true('stale' not in cfg.pspnl.assoc_get({"id": tx['id']}))


def assoc_sockless_bad(cfg):
    """ Test socket-less associations with bad arguments """
    _init_psp_dev(cfg)

    with ksft_raises(NlError) as cm:
        cfg.pspnl.rx_spi_alloc({"dev-id": cfg.psp_dev_id + 1234567,
                                "version": 0})
    ksft_eq(cm.exception.nl_msg.error, -errno.ENODEV)

    with ksft_raises(NlError) as cm:
        cfg.pspnl.assoc_add({"dev-id": cfg.psp_dev_id + 1234567,
                             "version": 0,
                             "tx-key": {"spi": 1, "key": b'\0' * 16}})
    ksft_eq(cm.exception.nl_msg.error, -errno.ENODEV)

    # Key of the wrong size for the version
    with ksft_raises(NlError) as cm:
        cfg.pspnl.assoc_add({"dev-id": cfg.psp_dev_id,
                             "version": 0,
                             "tx-key": {"spi": 1, "key": b'\0' * 32}})
    ksft_eq(cm.exception.nl_msg.error, -errno.EINVAL)

    with ksft_raises(NlError) as cm:
        cfg.pspnl.assoc_add({"dev-id": cfg.psp_dev_id, "version": 0})
    ksft_eq(cm.exception.nl_msg.error, -errno.EINVAL)


def assoc_sockless_tc(cfg):
    """ Test the tc psp action takes the right kind of assoc """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    rx, tx = _sockless_assocs(cfg)
    unknown = max(x['id'] for x in cfg.pspnl.assoc_get({}, dump=True)) + 1

    # encap takes a Tx assoc, decap none
    for act in (f"encap assoc {unknown}", f"encap assoc {rx['id']}",
                f"decap assoc {rx['id']}", f"decap assoc {tx['id']}"):
        ret = cmd(f"tc action add action psp {act}", fail=False)
        ksft_ne(ret.ret, 0, comment=act)

    for act in (f"encap assoc {tx['id']}", "decap"):
        tc(f"action add action psp {act} index 100")
        defer(tc, "action del action psp index 100").exec()


def assoc_sockless_tc_tunnel(cfg):
    """ Test the tunnel mode argument of the tc psp action """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    _, tx = _sockless_assocs(cfg)

    tc(f"action add action psp encap assoc {tx['id']} mode tunnel index 100")
    defer(tc, "action del action psp index 100")
    tc("action add action psp decap mode tunnel index 101")
    defer(tc, "action del action psp index 101")

    def get_act(index):
        out = tc(f"actions get action psp index {index}", json=True)
        return [x for x in out if "actions" in x][0]["actions"][0]

    ksft_eq(get_act(100).get("mode"), "tunnel")
    ksft_eq(get_act(101).get("mode"), "tunnel")


@ksft_variants(_get_psp_ver_ip_variants())
def data_tc_basic_send(cfg, version, ipver):
    """ Test data send with socket-less assocs and the tc psp action """
    cfg.require_ipver(ipver)
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)
    if version:
        _require_psp_version(cfg, version)

    rx_pkts = _get_stat(cfg, 'rx-packets')
    tx_pkts = _get_stat(cfg, 'tx-packets')

    s, _, _ = _tc_psp_conn(cfg, version, ipver)

    data_len = _send_careful(cfg, s, 100)
    _check_data_rx(cfg, data_len)
    # ... and the ACKs got through decap
    _check_data_outq(s, 0)

    ksft_gt(_get_stat(cfg, 'rx-packets'), rx_pkts)
    ksft_gt(_get_stat(cfg, 'tx-packets'), tx_pkts)
    ksft_gt(_tc_action_stats(cfg, "ingress")["packets"], 0)
    ksft_gt(_tc_action_stats(cfg, "egress")["packets"], 0)
    _close_psp_conn(cfg, s)


def data_tc_no_decap(cfg):
    """ Test decrypted packets don't reach a plain socket without decap """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    s, _, _ = _tc_psp_conn(cfg, 0, cfg.addr_ipver, decap=False)

    # Without ACKs we can't send more than the initial window
    data_len = _send_careful(cfg, s, 1)
    _check_data_rx(cfg, data_len)
    # The responder's ACKs come encrypted, and get dropped
    _check_data_outq(s, data_len, force_wait=True)
    _close_psp_conn(cfg, s)


def data_tc_assoc_del(cfg):
    """ Test deleting assocs while tc uses them: encap holds its Tx one """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    s, rx, tx = _tc_psp_conn(cfg, 0, cfg.addr_ipver)

    data_len = _send_careful(cfg, s, 10)
    _check_data_rx(cfg, data_len)

    cfg.pspnl.assoc_del({"id": rx['id']})
    cfg.pspnl.assoc_del({"id": tx['id']})

    data_len += _send_careful(cfg, s, 10)
    _check_data_rx(cfg, data_len)
    _check_data_outq(s, 0)
    _close_psp_conn(cfg, s)


def data_tc_decap_match(cfg):
    """ Test decap only takes what the filter's PSP matches allow """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    ipver = cfg.addr_ipver
    s, rx, _ = _tc_psp_conn(cfg, 0, ipver)
    spi, dev = rx['rx-key']['spi'], cfg.psp_dev_id

    def match(m_spi, m_ver, m_dev):
        return f"psp_spi {m_spi:#x} psp_ver {m_ver} psp_dev {m_dev}"

    data_len = _send_careful(cfg, s, 10)
    _check_data_rx(cfg, data_len)
    _check_data_outq(s, 0)

    # flower can only replace a filter with one matching the same keys
    def decap_filter(keys):
        tc(f"filter replace dev {cfg.ifname} ingress pref 10 handle 1 "
           f"protocol {_tc_proto(ipver)} flower {keys} action psp decap")

    for keys in (match(spi ^ 1, 0, dev), match(spi, 1, dev),
                 match(spi, 0, dev + 1)):
        # The responder's ACKs don't match, and the socket drops them
        decap_filter(keys)
        n = _send_careful(cfg, s, 1)
        data_len += n
        _check_data_rx(cfg, data_len)
        _check_data_outq(s, n, force_wait=True)

        # Once they match again, the retransmits get through
        decap_filter(match(spi, 0, dev))
        _wait_data_outq(s, 0)
    _close_psp_conn(cfg, s)


def data_tc_tunnel_sw(cfg):
    """ Test tunnel mode encap drops in software """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    ipver = cfg.addr_ipver
    s, _, tx = _tc_psp_conn(cfg, 0, ipver)

    # Only hardware offload implements tunnel mode
    sport = s.getsockname()[1]
    tc(f"filter replace dev {cfg.ifname} egress pref 10 handle 1 "
       f"protocol {_tc_proto(ipver)} flower ip_proto tcp src_port {sport} "
       f"action psp encap assoc {tx['id']} mode tunnel")

    data_len = _send_careful(cfg, s, 1)
    _check_data_outq(s, data_len, force_wait=True)
    _check_data_rx(cfg, 0)
    ksft_gt(_tc_action_stats(cfg, "egress")["drops"], 0)
    _close_psp_conn(cfg, s)


def data_tc_encap_wrong_dev(cfg):
    """ Test packets with an assoc sent to another device are dropped """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    ip("link add psp-dummy0 type dummy")
    defer(ip, "link del psp-dummy0")
    ip("link set psp-dummy0 up")

    ipver = cfg.addr_ipver
    s, _, tx = _tc_psp_conn(cfg, 0, ipver)

    sport = s.getsockname()[1]
    tc(f"filter replace dev {cfg.ifname} egress pref 10 handle 1 "
       f"protocol {_tc_proto(ipver)} flower ip_proto tcp src_port {sport} "
       f"action psp encap assoc {tx['id']} pipe "
       f"action mirred egress redirect dev psp-dummy0")

    def dummy_drops():
        dev = ip("-s link show dev psp-dummy0", json=True)[0]
        return dev['stats64']['tx']['dropped']

    drops = dummy_drops()
    data_len = _send_careful(cfg, s, 10)
    _check_data_outq(s, data_len, force_wait=True)
    _check_data_rx(cfg, 0)
    ksft_gt(dummy_drops(), drops)
    _close_psp_conn(cfg, s)


def data_tc_encap_short_hdr(cfg):
    """ Test encap drops an IPv4 packet shorter than its header length """
    cfg.require_ipver("4")
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    _, tx = _sockless_assocs(cfg)
    loc, rem = cfg.addr_v["4"], cfg.remote_addr_v["4"]
    _tc_clsact(cfg.ifname)
    # An IP protocol nothing else sends, so the filter only takes the
    # test's frame
    tc(f"filter add dev {cfg.ifname} egress pref 10 handle 1 protocol ip "
       f"flower ip_proto 0xfd dst_ip {rem} "
       f"action psp encap assoc {tx['id']}")
    defer(tc, f"filter del dev {cfg.ifname} egress pref 10 handle 1 "
          f"protocol ip flower")

    # A 20 byte IPv4 header which claims 60 (ihl 15), and nothing after
    # it. Encap must not take the 40 missing bytes for header. (Its total
    # length check would drop it too: this covers the IPv4 length checks
    # together.)
    iph = struct.pack("!BBHHHBBH4s4s", 0x4f, 0, 60, 0, 0, 64, 253, 0,
                      socket.inet_aton(loc), socket.inet_aton(rem))
    eth = (b"\xff" * 6 + bytes.fromhex(cfg.dev["address"].replace(":", "")) +
           struct.pack("!H", 0x0800))

    drops = _tc_action_stats(cfg, "egress")["drops"]
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as ps:
        ps.bind((cfg.ifname, 0x0800))
        try:
            ps.send(eth + iph)
        except OSError as e:
            # The drop on egress is reported to the sender
            if e.errno != errno.ENOBUFS:
                raise
    ksft_eq(_tc_action_stats(cfg, "egress")["drops"], drops + 1,
            comment="short IPv4 header dropped by encap")


def data_tc_encap_too_big(cfg):
    """ Test packets too big for the MTU once encapsulated are dropped """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    ipver = cfg.addr_ipver
    _, tx = _sockless_assocs(cfg)
    port = rand_port(socket.SOCK_DGRAM)
    _tc_clsact(cfg.ifname)
    tc(f"filter add dev {cfg.ifname} egress pref 10 handle 1 "
       f"protocol {_tc_proto(ipver)} flower ip_proto udp dst_port {port} "
       f"action psp encap assoc {tx['id']}")
    defer(tc, f"filter del dev {cfg.ifname} egress pref 10 handle 1 "
          f"protocol {_tc_proto(ipver)} flower")

    # The UDP payload which fits the MTU once the device adds UDP, the PSP
    # header and the ICV (40 bytes)
    mtu = ip(f"link show dev {cfg.ifname}", json=True)[0]['mtu']
    room = mtu - 40 - (20 if ipver == "4" else 40) - 8

    family = socket.AF_INET if ipver == "4" else socket.AF_INET6
    dst = (cfg.remote_addr_v[ipver], port)
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.sendto(b'x' * room, dst)
        with ksft_raises(OSError) as cm:
            s.sendto(b'x' * (room + 1), dst)
        ksft_eq(cm.exception.errno, errno.EMSGSIZE)

        # GSO (UDP_SEGMENT): each segment must fit
        s.setsockopt(socket.IPPROTO_UDP, UDP_SEGMENT, room)
        s.sendto(b'x' * room * 2, dst)
        s.setsockopt(socket.IPPROTO_UDP, UDP_SEGMENT, room + 1)
        with ksft_raises(OSError) as cm:
            s.sendto(b'x' * (room + 1) * 2, dst)
        ksft_eq(cm.exception.errno, errno.EMSGSIZE)
    ksft_ge(_tc_action_stats(cfg, "egress")["packets"], 4)


def data_tc_encap_psp_sock(cfg):
    """
    Test psp encap drops packets of a PSP socket, which already have a crypto
    offload
    """

    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    s = _make_psp_conn(cfg)
    defer(_tc_conn_close, cfg, s)
    rx = cfg.pspnl.rx_assoc({"version": 0,
                             "dev-id": cfg.psp_dev_id,
                             "sock-fd": s.fileno()})['rx-key']
    tx = _spi_xchg(s, rx)
    cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                        "version": 0,
                        "tx-key": tx,
                        "sock-fd": s.fileno()})
    data_len = _send_careful(cfg, s, 10)
    _check_data_rx(cfg, data_len)

    _, sl_tx = _sockless_assocs(cfg)
    _tc_clsact(cfg.ifname)
    sport = s.getsockname()[1]
    tc(f"filter add dev {cfg.ifname} egress pref 10 handle 1 "
       f"protocol {_tc_proto(cfg.addr_ipver)} flower ip_proto tcp "
       f"src_port {sport} action psp encap assoc {sl_tx['id']}")
    flt = defer(tc, f"filter del dev {cfg.ifname} egress pref 10 handle 1 "
                f"protocol {_tc_proto(cfg.addr_ipver)} flower")

    n = _send_careful(cfg, s, 1)
    _check_data_outq(s, n, force_wait=True)
    _check_data_rx(cfg, data_len)
    ksft_gt(_tc_action_stats(cfg, "egress")["drops"], 0)

    # Without the rule, the retransmits get through
    flt.exec()
    _wait_data_outq(s, 0)
    _check_data_rx(cfg, data_len + n)
    _close_psp_conn(cfg, s)


def data_tc_encap_ingress(cfg):
    """ Test packets with an assoc aren't redirected to ingress """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    _, tx = _sockless_assocs(cfg)
    # Traffic to a local address leaves through lo, and comes back on its
    # ingress. With the dst gone, input routing takes a loopback source for
    # a martian, and needs accept_local for a local one.
    sysctl = "net.ipv4.conf.lo.accept_local"
    old = cmd(f"sysctl -n {sysctl}").stdout.strip()
    cmd(f"sysctl -w {sysctl}=1")
    defer(cmd, f"sysctl -w {sysctl}={old}")
    ip("link add psp-dummy1 type dummy")
    defer(ip, "link del psp-dummy1")
    ip("addr add 203.0.113.1/32 dev psp-dummy1")
    fams = [(socket.AF_INET, "203.0.113.1", "ip")]
    if cmd("ip addr add 2001:db8:ff::1/128 dev psp-dummy1 nodad",
           fail=False).ret == 0:
        fams.append((socket.AF_INET6, "2001:db8:ff::1", "ipv6"))
    else:
        ksft_pr("no IPv6 on psp-dummy1, IPv4 only")
    ip("link set psp-dummy1 up")
    _tc_clsact("lo")
    for family, addr, proto in fams:
        with socket.socket(family, socket.SOCK_DGRAM) as srv, \
             socket.socket(family, socket.SOCK_DGRAM) as s:
            srv.bind((addr, 0))
            srv.settimeout(0.5)
            port = srv.getsockname()[1]
            flt = (f"dev lo egress pref 10 handle 1 protocol {proto} "
                   f"flower ip_proto udp dst_port {port}")
            redir = "action mirred ingress redirect dev lo"

            tc(f"filter add {flt} {redir}")
            del_flt = defer(tc, "filter del dev lo egress pref 10 "
                            f"handle 1 protocol {proto} flower")
            s.sendto(b'clear', (addr, port))
            ksft_eq(srv.recv(64), b'clear', comment=proto)

            # After encap the packet is marked decrypted: received, that
            # would read as decrypted by the device
            tc(f"filter replace {flt} action psp encap assoc {tx['id']} "
               f"pipe {redir}")
            s.sendto(b'encap', (addr, port))
            with ksft_raises(socket.timeout):
                srv.recv(64)
            flts = tc("-s filter show dev lo egress pref 10", json=True)
            mirred = [a["stats"] for f in flts
                      for a in f.get("options", {}).get("actions", [])
                      if a["kind"] == "mirred"]
            ksft_eq(mirred[0]["overlimits"], 1, comment=proto)
            del_flt.exec()


def _tc_act_stats(dev, pref, host=None):
    """ Stats of the first action of the ingress filter @pref of @dev """
    filters = tc(f"-s filter show dev {dev} ingress pref {pref}",
                 json=True, host=host)
    for flt in filters:
        for act in flt.get("options", {}).get("actions", []):
            return act["stats"]
    raise KsftFailEx(f"no action on the {dev} pref {pref} filter")


def _tc_act_pkts(dev, pref, host=None):
    """ Packets of the first action of the ingress filter @pref of @dev """
    return _tc_act_stats(dev, pref, host)["packets"]


def _fwd_client(cfg, ipver, mtu=None):
    """
    Set up a client in a netns behind veth psp-fwd0, and forward its
    traffic: only from psp-fwd0, the host's own forwarding settings stay as
    they are. Return a UDP socket of the client.
    """
    ns = NetNS()
    defer(ns.__del__)
    ip(f"link add psp-fwd0 type veth peer name psp-fwd1 netns {ns.name}")
    defer(ip, "link del psp-fwd0")
    if ipver == "4":
        fwd = "/proc/sys/net/ipv4/conf/psp-fwd0/forwarding"
        local, client, plen = "198.51.100.1", "198.51.100.2", 24
    else:
        fwd = "/proc/sys/net/ipv6/conf/psp-fwd0/force_forwarding"
        local, client, plen = "2001:db8:fe::1", "2001:db8:fe::2", 64
    if not os.path.exists(fwd):
        raise KsftSkipEx(f"{fwd} not supported")
    # Goes away with the device
    with open(fwd, "w", encoding="utf-8") as fp:
        fp.write("1")
    if mtu:
        ip(f"link set psp-fwd0 mtu {mtu}")
        ip(f"-n {ns.name} link set psp-fwd1 mtu {mtu}")
    # IPv6 may be disabled on new devices
    if cmd(f"ip addr add {local}/{plen} dev psp-fwd0 nodad",
           fail=False).ret:
        raise KsftSkipEx(f"can't add {local} to a new device")
    ip("link set psp-fwd0 up")
    ip(f"-n {ns.name} addr add {client}/{plen} dev psp-fwd1 nodad")
    ip(f"-n {ns.name} link set psp-fwd1 up")
    ip(f"-n {ns.name} route add default via {local}")

    family = socket.AF_INET if ipver == "4" else socket.AF_INET6
    with NetNSEnter(ns.name):
        s = socket.socket(family, socket.SOCK_DGRAM)
    defer(s.close)
    return s


def _remote_filter(cfg, pref, proto, match):
    """
    Add a flower filter on the remote's ingress, to count what gets there.
    In software only: drivers refresh the counters of offloaded filters
    periodically, and these counts must be exact.
    """
    _tc_clsact(cfg.remote_ifname, host=cfg.remote)
    tc(f"filter add dev {cfg.remote_ifname} ingress pref {pref} handle 1 "
       f"protocol {proto} flower skip_hw {match}", host=cfg.remote)
    defer(tc, f"filter del dev {cfg.remote_ifname} ingress pref {pref} "
          f"handle 1 protocol {proto} flower", host=cfg.remote)


def _tc_encap_ingress(proto, port, tx):
    """ psp encap on psp-fwd0's ingress, which software drops """
    _tc_clsact("psp-fwd0")
    tc(f"filter add dev psp-fwd0 ingress pref 10 protocol {proto} "
       f"flower ip_proto udp dst_port {port} "
       f"action psp encap assoc {tx['id']}")


@ksft_variants(_get_ip_variants())
def data_tc_encap_routed(cfg, ipver):
    """ Test software encap on ingress drops routed packets """
    cfg.require_ipver(ipver)
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    proto = _tc_proto(ipver)
    _, tx = _sockless_assocs(cfg)
    s = _fwd_client(cfg, ipver)

    port = rand_port(socket.SOCK_DGRAM)
    _remote_filter(cfg, 10, proto,
                   f"ip_proto udp dst_port {port} action drop")

    def remote_pkts():
        return _tc_act_pkts(cfg.remote_ifname, 10, host=cfg.remote)

    def send(n):
        for _ in range(n):
            s.sendto(b'0123456789', (cfg.remote_addr_v[ipver], port))
            time.sleep(0.01)
        time.sleep(0.2)

    # Without encap the packets are forwarded to the remote, unless
    # something else, e.g. a FORWARD policy, stops them
    send(10)
    sent = remote_pkts()
    if not sent:
        raise KsftSkipEx("forwarded packets don't reach the remote")

    # Encap on ingress is hardware offload only: in software the action
    # drops the packets. They must not reach the remote in clear text.
    _tc_encap_ingress(proto, port, tx)
    send(10)
    ksft_eq(_tc_act_pkts("psp-fwd0", 10), 10)
    ksft_eq(_tc_act_stats("psp-fwd0", 10)["drops"], 10,
            comment="dropped by encap")
    ksft_eq(remote_pkts(), sent)


@ksft_variants(_get_ip_variants())
def data_tc_encap_local(cfg, ipver):
    """ Test software encap on ingress drops packets to a local address """
    cfg.require_ipver(ipver)
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)

    _, tx = _sockless_assocs(cfg)
    s = _fwd_client(cfg, ipver)
    fam = "inet" if ipver == "4" else "inet6"
    addrs = ip("addr show dev psp-fwd0", json=True)[0]["addr_info"]
    local = [a["local"] for a in addrs
             if a["family"] == fam and a["scope"] == "global"][0]

    family = socket.AF_INET if ipver == "4" else socket.AF_INET6
    with socket.socket(family, socket.SOCK_DGRAM) as srv:
        srv.bind((local, 0))
        srv.settimeout(0.5)
        port = srv.getsockname()[1]

        # Without encap the packets are delivered, unless something
        # else, e.g. an INPUT policy, stops them
        s.sendto(b'clear', (local, port))
        try:
            got = srv.recv(64)
        except socket.timeout as e:
            raise KsftSkipEx("the client's packets aren't delivered") from e
        ksft_eq(got, b'clear')

        # Encap on ingress is hardware offload only: in software the
        # action drops the packets, rather than let them be received
        _tc_encap_ingress(_tc_proto(ipver), port, tx)
        s.sendto(b'encap', (local, port))
        with ksft_raises(socket.timeout):
            srv.recv(64)
        ksft_eq(_tc_act_pkts("psp-fwd0", 10), 1)
        ksft_eq(_tc_act_stats("psp-fwd0", 10)["drops"], 1,
                comment="dropped by encap")


def data_tc_encap_routed_frag(cfg):
    """ Test encap drops the fragments of routed packets """
    _init_psp_dev(cfg)
    _require_tc_psp(cfg)
    cfg.require_ipver("4")
    _, tx = _sockless_assocs(cfg)

    # Datagrams which fit the veth but not our egress, and have no DF, get
    # fragmented when we forward them, before tc egress
    mtu = ip(f"link show dev {cfg.ifname}", json=True)[0]['mtu']
    s = _fwd_client(cfg, "4", mtu=mtu + 100)
    # IP_MTU_DISCOVER, IP_PMTUDISC_DONT: no DF
    s.setsockopt(socket.IPPROTO_IP, 10, 0)

    port = rand_port(socket.SOCK_DGRAM)
    rem = cfg.remote_addr_v["4"]
    _remote_filter(cfg, 5, "ip", "ip_flags frag action continue")

    def remote_frags():
        return _tc_act_pkts(cfg.remote_ifname, 5, host=cfg.remote)

    def send(n):
        for _ in range(n):
            s.sendto(b'x' * mtu, (rem, port))
            time.sleep(0.01)
        time.sleep(0.2)

    # Without encap the datagrams are forwarded, in fragments, unless
    # something else, e.g. a FORWARD policy, stops them
    send(5)
    frags = remote_frags()
    if not frags:
        raise KsftSkipEx("forwarded fragments don't reach the remote")

    # Encap on our egress, matching the fragments by address: only the
    # first one carries the UDP header, a port match would miss the
    # others. Transport mode can't carry fragments, encap drops them all,
    # and none may reach the remote in clear text.
    _tc_clsact(cfg.ifname)
    tc(f"filter add dev {cfg.ifname} egress pref 10 handle 1 protocol ip "
       f"flower dst_ip {rem} ip_flags frag "
       f"action psp encap assoc {tx['id']}")
    defer(tc, f"filter del dev {cfg.ifname} egress pref 10 handle 1 "
          f"protocol ip flower")
    send(5)
    stats = _tc_action_stats(cfg, "egress")
    ksft_gt(stats["packets"], 0)
    ksft_eq(stats["drops"], stats["packets"], comment="dropped by encap")
    ksft_eq(remote_frags(), frags)


def removal_device_tc(cfg):
    """ Test removing a PSD with tc actions holding its assocs """
    cfg.require_nsim()
    _require_tc_psp(cfg)
    # Only look the device up: enabling PSP would register an undo for the
    # device which the test removes
    if not hasattr(cfg, 'psp_dev_id'):
        for dev in cfg.pspnl.dev_get({}, dump=True):
            if dev['ifindex'] == cfg.ifindex:
                cfg.psp_info = dev
                cfg.psp_dev_id = dev['id']
                break
        else:
            raise KsftSkipEx("No PSP devices found")

    rx, tx = _sockless_assocs(cfg)
    tc(f"action add action psp encap assoc {tx['id']} index 100")
    defer(tc, "action del action psp index 100")

    __nsim_psp_rereg(cfg)

    # Unregistering the device drops its socket-less assocs
    for assoc_id in (rx['id'], tx['id']):
        with ksft_raises(NlError) as cm:
            cfg.pspnl.assoc_get({"id": assoc_id})
        ksft_eq(cm.exception.nl_msg.error, -errno.ENOENT)


def _check_assoc_list(cfg, psp_dev_id, ifindex, nsid=None):
    """Verify assoc-list contains device with given ifindex, no duplicates."""
    dev_info = cfg.pspnl.dev_get({'id': psp_dev_id})

    ksft_true('assoc-list' in dev_info,
              "No assoc-list in dev_get() response after association")
    found = False
    for assoc in dev_info['assoc-list']:
        if assoc['ifindex'] != ifindex:
            continue
        if nsid is not None and assoc['nsid'] != nsid:
            continue
        ksft_eq(found, False, "Duplicate assoc entry found")
        found = True
    ksft_eq(found, True,
            "Associated device not found in dev_get() response")


def _data_basic_send_netkit_psp_assoc(cfg, version, ipver):
    """
    Test basic data send with netkit interface associated with PSP dev.
    """
    _assoc_nk_guest(cfg)

    # Enter guest namespace (netns) to run PSP test
    with NetNSEnter(cfg.netns.name):
        cfg.pspnl = PSPFamily()

        sock = _make_psp_conn(cfg, version, ipver)

        rx_assoc = cfg.pspnl.rx_assoc({"version": version,
                                       "dev-id": cfg.psp_dev_id,
                                       "sock-fd": sock.fileno()})
        rx_key = rx_assoc['rx-key']
        tx_key = _spi_xchg(sock, rx_key)

        cfg.pspnl.tx_assoc({"dev-id": cfg.psp_dev_id,
                            "version": version,
                            "tx-key": tx_key,
                            "sock-fd": sock.fileno()})

        data_len = _send_careful(cfg, sock, 100)
        _check_data_rx(cfg, data_len)
        _close_psp_conn(cfg, sock)


def _assoc_check_list(cfg):
    """Test that assoc-list is correctly populated after dev-assoc."""
    _assoc_nk_guest(cfg)
    _check_assoc_list(cfg, cfg.psp_dev_id, cfg.nk_guest_ifindex,
                      cfg.psp_dev_peer_nsid)


def _get_psp_ver_ip6_variants():
    for ver in range(4):
        yield KsftNamedVariant(f"v{ver}_ip6", ver, "6")


@ksft_variants(_get_psp_ver_ip6_variants())
def data_basic_send_netkit_psp_assoc(cfg, version, ipver):
    """Test PSP data send via netkit with dev-assoc."""
    cfg.require_ipver(ipver)
    _data_basic_send_netkit_psp_assoc(cfg, version, ipver)


def _key_rotation_notify_multi_ns_netkit(cfg):
    """ Test key rotation notifications across multiple namespaces using netkit """
    _assoc_nk_guest(cfg)

    # Create listener in guest namespace; socket stays bound to that ns
    with NetNSEnter(cfg.netns.name):
        peer_pspnl = PSPFamily()
        peer_pspnl.ntf_subscribe('use')

    # Create listener in main namespace
    main_pspnl = PSPFamily()
    main_pspnl.ntf_subscribe('use')

    # Trigger key rotation on the PSP device
    cfg.pspnl.key_rotate({"id": cfg.psp_dev_id})

    # Poll both sockets from main thread
    for pspnl, label in [(main_pspnl, "main"), (peer_pspnl, "guest")]:
        for ntf in pspnl.poll_ntf(duration=10):
            if ntf['msg'].get('id') == cfg.psp_dev_id:
                break
        else:
            raise KsftFailEx(
                f"No key rotation notification received"
                f" in {label} namespace")


def _dev_change_notify_multi_ns_netkit(cfg):
    """ Test dev_change notifications across multiple namespaces using netkit """
    _assoc_nk_guest(cfg)

    # Create listener in guest namespace; socket stays bound to that ns
    with NetNSEnter(cfg.netns.name):
        peer_pspnl = PSPFamily()
        peer_pspnl.ntf_subscribe('mgmt')

    # Create listener in main namespace
    main_pspnl = PSPFamily()
    main_pspnl.ntf_subscribe('mgmt')

    # Trigger dev_change by calling dev_set (notification is always sent)
    cfg.pspnl.dev_set({'id': cfg.psp_dev_id,
                       'psp-versions-ena': cfg.psp_info['psp-versions-cap']})

    # Poll both sockets from main thread
    for pspnl, label in [(main_pspnl, "main"), (peer_pspnl, "guest")]:
        for ntf in pspnl.poll_ntf(duration=10):
            if ntf['msg'].get('id') == cfg.psp_dev_id:
                break
        else:
            raise KsftFailEx(
                f"No dev_change notification received"
                f" in {label} namespace")


def _subscribe_mgmt(cfg):
    """Listen on the mgmt group in the guest and in the main namespace."""
    # Listener in the guest namespace; socket stays bound to that ns
    with NetNSEnter(cfg.netns.name):
        peer_pspnl = PSPFamily()
        peer_pspnl.ntf_subscribe('mgmt')

    main_pspnl = PSPFamily()
    main_pspnl.ntf_subscribe('mgmt')

    return main_pspnl, peer_pspnl


def _get_dev_ntf(cfg, pspnl, label):
    """Wait for the next notification about the PSP device under test."""
    for ntf in pspnl.poll_ntf(duration=10):
        if ntf['msg'].get('id') == cfg.psp_dev_id:
            return ntf
    raise KsftFailEx(f"No notification received in the {label} namespace")


def _check_disassoc_ntf(cfg, main_pspnl, peer_pspnl, ifindex):
    """Check the notifications for a netns losing its last association."""
    ntf = _get_dev_ntf(cfg, main_pspnl, "main")
    ksft_eq(ntf['name'], 'dev-change-ntf')
    for assoc in ntf['msg'].get('assoc-list', []):
        if assoc['nsid'] != cfg.psp_dev_peer_nsid:
            continue
        ksft_ne(assoc['ifindex'], ifindex,
                "Disassociated device still listed in the notification")

    # The device is gone as far as the disassociated namespace is concerned
    ntf = _get_dev_ntf(cfg, peer_pspnl, "guest")
    ksft_eq(ntf['name'], 'dev-del-ntf')
    ksft_true('ifindex' not in ntf['msg'],
              "ifindex reported to an associated namespace")


def _dev_disassoc_notify_multi_ns_netkit(cfg):
    """ Test the notifications dev-disassoc generates in both namespaces """
    _init_psp_dev(cfg, True)
    defer(delattr, cfg, 'psp_dev_id')
    defer(delattr, cfg, 'psp_info')

    cfg.pspnl.dev_assoc({'id': cfg.psp_dev_id,
                         'ifindex': cfg.nk_guest_ifindex,
                         'nsid': cfg.psp_dev_peer_nsid})
    defer(_try_disassoc, cfg, cfg.psp_dev_id, cfg.nk_guest_ifindex,
          cfg.psp_dev_peer_nsid)

    main_pspnl, peer_pspnl = _subscribe_mgmt(cfg)

    cfg.pspnl.dev_disassoc({'id': cfg.psp_dev_id,
                            'ifindex': cfg.nk_guest_ifindex,
                            'nsid': cfg.psp_dev_peer_nsid})

    _check_disassoc_ntf(cfg, main_pspnl, peer_pspnl, cfg.nk_guest_ifindex)


def _dev_disassoc_notify_one_of_two_netkit(cfg):
    """Test the notifications with two netkits associated in one netns.

    Disassociating the first netkit leaves the PSP device visible in the
    guest namespace, generates a dev-change-ntf.
    Disassociating the second one takes the device out of its view,
    generates 'dev-del-ntf'.
    """
    _init_psp_dev(cfg, True)
    defer(delattr, cfg, 'psp_dev_id')
    defer(delattr, cfg, 'psp_info')

    tmp_ifindex, _ = _add_netkit_guest(cfg, "tmp_nk_host", "tmp_nk_guest")

    for ifindex in [cfg.nk_guest_ifindex, tmp_ifindex]:
        cfg.pspnl.dev_assoc({'id': cfg.psp_dev_id, 'ifindex': ifindex,
                             'nsid': cfg.psp_dev_peer_nsid})
        defer(_try_disassoc, cfg, cfg.psp_dev_id, ifindex,
              cfg.psp_dev_peer_nsid)

    main_pspnl, peer_pspnl = _subscribe_mgmt(cfg)

    # One of the two goes away, the device stays visible in the guest netns
    cfg.pspnl.dev_disassoc({'id': cfg.psp_dev_id, 'ifindex': tmp_ifindex,
                            'nsid': cfg.psp_dev_peer_nsid})

    ntf = _get_dev_ntf(cfg, main_pspnl, "main")
    ksft_eq(ntf['name'], 'dev-change-ntf')

    ntf = _get_dev_ntf(cfg, peer_pspnl, "guest")
    ksft_eq(ntf['name'], 'dev-change-ntf')
    found = False
    for assoc in ntf['msg'].get('assoc-list', []):
        ksft_ne(assoc['ifindex'], tmp_ifindex,
                "Disassociated device still listed in the notification")
        found |= assoc['ifindex'] == cfg.nk_guest_ifindex
    ksft_true(found, "Remaining association missing from the notification")

    # And now the last one, the device disappears from the guest netns
    cfg.pspnl.dev_disassoc({'id': cfg.psp_dev_id,
                            'ifindex': cfg.nk_guest_ifindex,
                            'nsid': cfg.psp_dev_peer_nsid})

    _check_disassoc_ntf(cfg, main_pspnl, peer_pspnl, cfg.nk_guest_ifindex)


def _psp_dev_get_check_netkit_psp_assoc(cfg):
    """ Check psp dev-get output with netkit interface associated with PSP dev """
    _assoc_nk_guest(cfg)

    # Check 1: In default netns, verify dev-get has correct ifindex and assoc-list
    dev_info = cfg.pspnl.dev_get({'id': cfg.psp_dev_id})
    ksft_eq(dev_info['ifindex'], cfg.psp_ifindex)
    _check_assoc_list(cfg, cfg.psp_dev_id, cfg.nk_guest_ifindex,
                      cfg.psp_dev_peer_nsid)

    # Check 2: In guest netns, verify dev-get has assoc-list with nk_guest device
    with NetNSEnter(cfg.netns.name):
        peer_pspnl = PSPFamily()

        # Dump all devices in the guest namespace
        peer_devices = peer_pspnl.dev_get({}, dump=True)

        # Find the device with by-association flag
        peer_dev = None
        for dev in peer_devices:
            if dev.get('by-association'):
                peer_dev = dev
                break

        ksft_not_none(peer_dev, "No PSP device found with by-association flag in guest netns")

        # ifindex of the main netdevice means nothing in this namespace
        ksft_true('ifindex' not in peer_dev,
                  "ifindex reported to an associated namespace")

        # Verify assoc-list contains the nk_guest device
        ksft_true('assoc-list' in peer_dev and len(peer_dev['assoc-list']) > 0,
                  "Guest device should have assoc-list with local devices")

        # Verify the assoc-list contains nk_guest ifindex with nsid=-1 (same namespace)
        found = False
        for assoc in peer_dev['assoc-list']:
            if assoc['ifindex'] == cfg.nk_guest_ifindex:
                ksft_eq(assoc['nsid'], -1,
                        "nsid should be -1 (NETNSA_NSID_NOT_ASSIGNED) for same-namespace device")
                found = True
                break
        ksft_true(found, "nk_guest ifindex not found in assoc-list")


def _dev_assoc_no_nsid(cfg):
    """ Test dev-assoc and dev-disassoc without nsid attribute """
    _init_psp_dev(cfg, True)

    # Associate without nsid - should look up ifindex in caller's netns
    cfg.pspnl.dev_assoc({'id': cfg.psp_dev_id,
                         'ifindex': cfg.nk_host_ifindex})
    defer(_try_disassoc, cfg,
          cfg.psp_dev_id, cfg.nk_host_ifindex)
    defer(delattr, cfg, 'psp_dev_id')
    defer(delattr, cfg, 'psp_info')

    # Verify assoc-list contains the device (match by ifindex only)
    _check_assoc_list(cfg, cfg.psp_dev_id, cfg.nk_host_ifindex)

    # Disassociate without nsid - should also use caller's netns
    cfg.pspnl.dev_disassoc({'id': cfg.psp_dev_id,
                            'ifindex': cfg.nk_host_ifindex})

    # Verify assoc-list no longer contains the device
    dev_info = cfg.pspnl.dev_get({'id': cfg.psp_dev_id})
    found = False
    if 'assoc-list' in dev_info:
        for assoc in dev_info['assoc-list']:
            if assoc['ifindex'] == cfg.nk_host_ifindex:
                found = True
                break
    ksft_true(not found, "Device should not be in assoc-list after disassociation")


def _add_netkit_guest(cfg, host_name, guest_name):
    """Create a netkit pair and move its peer into the test namespace.

    Returns the peer's ifindex there and the defer() deleting the pair.
    """
    existing = {link['ifindex'] for link in ip("-d link show", json=True)
                if link.get('linkinfo', {}).get('info_kind') == 'netkit'}

    rtnl = RtnlFamily()
    rtnl.newlink(
        {
            "ifname": host_name,
            "linkinfo": {
                "kind": "netkit",
                "data": {
                    "mode": "l2",
                    "policy": "forward",
                    "peer-policy": "forward",
                },
            },
        },
        flags=[Netlink.NLM_F_CREATE, Netlink.NLM_F_EXCL],
    )
    cleanup = defer(ip, f"link del {host_name}")

    # Find the peer by diffing against existing netkit ifindexes
    all_links = ip("-d link show", json=True)
    peer = [link for link in all_links
            if link.get('linkinfo', {}).get('info_kind') == 'netkit'
            and link['ifindex'] not in existing
            and link['ifname'] != host_name]
    ksft_eq(len(peer), 1, "Failed to find the new netkit peer")

    # Rename and move guest end into the test namespace
    ip(f"link set dev {peer[0]['ifname']} name {guest_name}")
    ip(f"link set dev {guest_name} netns {cfg.netns.name}")
    guest_dev = ip(f"link show dev {guest_name}", json=True, ns=cfg.netns)[0]
    ip(f"link set dev {guest_name} up", ns=cfg.netns)

    return guest_dev['ifindex'], cleanup


def _psp_dev_assoc_cleanup_on_netkit_del(cfg):
    """Test that assoc-list is cleared when associated netkit is deleted.

    Creates a disposable netkit pair for this test to avoid destroying
    the shared environment.
    """
    _init_psp_dev(cfg, True)
    defer(delattr, cfg, 'psp_dev_id')
    defer(delattr, cfg, 'psp_info')

    tmp_host_name = "tmp_nk_host"
    tmp_guest_ifindex, cleanup_netkit = _add_netkit_guest(cfg, tmp_host_name,
                                                          "tmp_nk_guest")

    # Associate PSP device with the temporary guest interface
    cfg.pspnl.dev_assoc({'id': cfg.psp_dev_id,
                         'ifindex': tmp_guest_ifindex,
                         'nsid': cfg.psp_dev_peer_nsid})

    # Verify assoc-list contains the temporary device
    _check_assoc_list(cfg, cfg.psp_dev_id, tmp_guest_ifindex,
                      cfg.psp_dev_peer_nsid)

    # Removing the netdevice is notified like a disassociation
    main_pspnl, peer_pspnl = _subscribe_mgmt(cfg)

    # Delete the temporary netkit pair (deleting one end removes both)
    ip(f"link del {tmp_host_name}")
    cleanup_netkit.cancel()

    # Verify assoc-list is cleared after netkit deletion
    dev_info = cfg.pspnl.dev_get({'id': cfg.psp_dev_id})
    ksft_true('assoc-list' not in dev_info
              or len(dev_info['assoc-list']) == 0,
              "assoc-list should be empty after netkit deletion")

    _check_disassoc_ntf(cfg, main_pspnl, peer_pspnl, tmp_guest_ifindex)


def _try_disassoc(cfg, psp_dev_id, ifindex, nsid=None):
    """Best-effort disassociate, ignoring errors if already removed."""
    try:
        params = {'id': psp_dev_id, 'ifindex': ifindex}
        if nsid is not None:
            params['nsid'] = nsid
        cfg.pspnl.dev_disassoc(params)
    except NlError:
        pass


def _assoc_nk_guest(cfg):
    """Associate nk_guest with PSP device and register cleanup via defer()."""
    _init_psp_dev(cfg, True)

    cfg.pspnl.dev_assoc({'id': cfg.psp_dev_id,
                         'ifindex': cfg.nk_guest_ifindex,
                         'nsid': cfg.psp_dev_peer_nsid})
    defer(_disassoc_nk_guest, cfg,
          cfg.psp_dev_id, cfg.nk_guest_ifindex)


def _disassoc_nk_guest(cfg, psp_dev_id, nk_guest_ifindex):
    """Disassociate nk_guest and reset cfg PSP state."""
    pspnl = PSPFamily()
    pspnl.dev_disassoc({'id': psp_dev_id, 'ifindex': nk_guest_ifindex,
                        'nsid': cfg.psp_dev_peer_nsid})
    cfg.pspnl = pspnl
    del cfg.psp_dev_id
    del cfg.psp_info


def _get_nsid(ns_name):
    """Get the nsid for a namespace."""
    for entry in ip("netns list-id", json=True):
        if entry.get("name") == str(ns_name):
            return entry["nsid"]
    raise KsftSkipEx(f"nsid not found for namespace {ns_name}")


def _setup_psp_attributes(cfg):
    # pylint: disable=protected-access
    """
    Set up PSP-specific attributes on the environment.

    This sets attributes needed for PSP tests based on whether we're using
    netdevsim or a real NIC.
    """
    if cfg._ns is not None:
        # netdevsim case: PSP device is the local dev (in host namespace)
        cfg.psp_dev = cfg._ns.nsims[0].dev
        cfg.psp_ifname = cfg.psp_dev['ifname']
        cfg.psp_ifindex = cfg.psp_dev['ifindex']

        # PSP peer device is the remote dev (in _netns, where psp_responder runs)
        cfg.psp_dev_peer = cfg._ns_peer.nsims[0].dev
        cfg.psp_dev_peer_ifname = cfg.psp_dev_peer['ifname']
        cfg.psp_dev_peer_ifindex = cfg.psp_dev_peer['ifindex']
    else:
        # Real NIC case: PSP device is the local interface
        cfg.psp_dev = cfg.dev
        cfg.psp_ifname = cfg.ifname
        cfg.psp_ifindex = cfg.ifindex

        # PSP peer device is the remote interface
        cfg.psp_dev_peer = cfg.remote_dev
        cfg.psp_dev_peer_ifname = cfg.remote_ifname
        cfg.psp_dev_peer_ifindex = cfg.remote_ifindex

    # Get nsid for the guest namespace (netns) where nk_guest is
    cfg.psp_dev_peer_nsid = _get_nsid(cfg.netns.name)



def main() -> None:
    """ Ksft boiler plate main """

    # Make sure LOCAL_PREFIX_V6 is set
    if "LOCAL_PREFIX_V6" not in os.environ:
        os.environ["LOCAL_PREFIX_V6"] = "2001:db8:2::"

    try:
        env = NetDrvContEnv(__file__, primary_rx_redirect=True)
        has_cont = True
    except KsftSkipEx:
        env = NetDrvEpEnv(__file__)
        has_cont = False

    with env as cfg:
        cfg.pspnl = PSPFamily()

        if has_cont:
            _setup_psp_attributes(cfg)

        # Set up responder and communication sock
        # psp_responder runs in _netns (remote namespace with psp_dev_peer)
        responder = cfg.remote.deploy("psp_responder")

        cfg.comm_port = rand_port()
        srv = None
        try:
            with bkg(responder + f" -p {cfg.comm_port} -i {cfg.remote_ifindex}",
                     host=cfg.remote, exit_wait=True) as srv:
                wait_port_listen(cfg.comm_port, host=cfg.remote)

                cfg.comm_sock = socket.create_connection((cfg.remote_addr,
                                                          cfg.comm_port),
                                                         timeout=1)

                cases = [data_basic_send, data_mss_adjust,
                         data_send_ipv6_exthdr, data_tc_basic_send,
                         data_tc_encap_routed, data_tc_encap_local]

                if has_cont:
                    cases += [
                        _assoc_check_list,
                        data_basic_send_netkit_psp_assoc,
                        _key_rotation_notify_multi_ns_netkit,
                        _dev_change_notify_multi_ns_netkit,
                        _dev_disassoc_notify_multi_ns_netkit,
                        _dev_disassoc_notify_one_of_two_netkit,
                        _psp_dev_get_check_netkit_psp_assoc,
                        _dev_assoc_no_nsid,
                        _psp_dev_assoc_cleanup_on_netkit_del,
                    ]

                ksft_run(cases=cases, globs=globals(),
                         case_pfx={"dev_", "data_", "assoc_", "removal_"},
                         args=(cfg, ))

                cfg.comm_sock.send(b"exit\0")
                cfg.comm_sock.close()
        finally:
            if srv and (srv.stdout or srv.stderr):
                ksft_pr("")
                ksft_pr(f"Responder logs ({srv.ret}):")
            if srv and srv.stdout:
                ksft_pr("STDOUT:\n#  " + srv.stdout.strip().replace("\n", "\n#  "))
            if srv and srv.stderr:
                ksft_pr("STDERR:\n#  " + srv.stderr.strip().replace("\n", "\n#  "))
    ksft_exit()


if __name__ == "__main__":
    main()
