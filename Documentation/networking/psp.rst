.. SPDX-License-Identifier: GPL-2.0-only

=====================
PSP Security Protocol
=====================

Protocol
========

PSP Security Protocol (PSP) was defined at Google and published in:

https://raw.githubusercontent.com/google/psp/main/doc/PSP_Arch_Spec.pdf

This section briefly covers protocol aspects crucial for understanding
the kernel API. Refer to the protocol specification for further details.

Note that the kernel implementation and documentation uses the term
"device key" in place of "master key", it is both less confusing
to an average developer and is less likely to run afoul any naming
guidelines.

Derived Rx keys
---------------

PSP borrows some terms and mechanisms from IPsec. PSP was designed
with HW offloads in mind. The key feature of PSP is that Rx keys for every
connection do not have to be stored by the receiver but can be derived
from device key and information present in packet headers.
This makes it possible to implement receivers which require a constant
amount of memory regardless of the number of connections (``O(1)`` scaling).

Tx keys have to be stored like with any other protocol, but Tx is much
less latency sensitive than Rx, and delays in fetching keys from slow
memory is less likely to cause packet drops. Preferably, the Tx keys
should be provided with the packet (e.g. as part of the descriptors).

Key rotation
------------

The device key known only to the receiver is fundamental to the design.
Per specification this state cannot be directly accessible (it must be
impossible to read it out of the hardware of the receiver NIC).
Moreover, it has to be "rotated" periodically (usually daily). Rotation
means that new device key gets generated (by a random number generator
of the device), and used for all new connections. To avoid disrupting
old connections the old device key remains in the NIC. A phase bit
carried in the packet headers indicates which generation of device key
the packet has been encrypted with.

User facing API
===============

PSP is designed primarily for hardware offloads. There is currently
no software fallback for systems which do not have PSP capable NICs.
There is also no standard (or otherwise defined) way of establishing
a PSP-secured connection or exchanging the symmetric keys.

The expectation is that higher layer protocols will take care of
protocol and key negotiation. For example one may use TLS key exchange,
announce the PSP capability, and switch to PSP if both endpoints
are PSP-capable.

All configuration of PSP is performed via the PSP netlink family.

Device discovery
----------------

The PSP netlink family defines operations to retrieve information
about the PSP devices available on the system, configure them and
access PSP related statistics.

PSP Associations
----------------

PSP encryption and decryption happen in the context of an association.
An association holds the PSP device, PSP version, and either Rx state
for decrypting and authenticating packets (the SPI, and for sockets the
Rx key), a Tx key for encrypting packets, or both.

Associations are used in two ways. First, a TCP socket can be bound to
an association, and all packets flowing over that socket inherit its
association. Second, socket-less associations, either Rx or Tx, are
used with tc. This allows PSP for forwarded traffic, or for non-TCP
traffic. A tc action attaches a Tx association to packets. An Rx
association reserves an SPI: the device decrypts packets sent to it,
and a tc filter matches the SPI, version and PSP device a packet was
decrypted with.

An association is of one type or the other; that is, sockets may not
use socket-less associations, and tc actions do not address associations
which are attached to a socket. Device statistics count both.

Securing a socket connection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PSP encryption can be enabled for TCP sockets. Other kinds of sockets
are not supported. For a TCP socket, Rx and Tx keys are allocated
separately. First the ``rx-assoc`` Netlink command needs to be issued,
specifying a target TCP socket. Kernel will allocate a new PSP Rx key
from the NIC, create an association with it, and bind it to the given
socket. At this stage socket will accept both PSP-secured and plain text
TCP packets.

The Tx key is installed into the socket's association with the
``tx-assoc`` Netlink command. Once it is installed, all data read from
the socket will be PSP-secured. In other words act of installing Tx keys
has a secondary effect on the Rx direction.

There is an intermediate period after ``tx-assoc`` successfully
returns and before the TCP socket encounters it's first PSP
authenticated packet, where the TCP stack will allow certain nondata
packets, i.e. ACKs, FINs, and RSTs, to enter TCP receive processing
even if not PSP authenticated. During the ``tx-assoc`` call, the TCP
socket's ``rcv_nxt`` field is recorded. At this point, ACKs and RSTs
will be accepted with any sequence number, while FINs will only be
accepted at the latched value of ``rcv_nxt``. Once the TCP stack
encounters the first TCP packet containing PSP authenticated data, the
other end of the connection must have executed the ``tx-assoc``
command, so any TCP packet, including those without data, will be
dropped before receive processing if it is not successfully
authenticated. This is summarized in the table below. The
aforementioned state of rejecting all non-PSP packets is labeled "PSP
Full".

+----------------+------------+------------+-------------+-------------+
| Event          | Normal TCP | Rx PSP     | Tx PSP      | PSP Full    |
+================+============+============+=============+=============+
| Rx plain       | accept     | accept     | drop        | drop        |
| (data)         |            |            |             |             |
+----------------+------------+------------+-------------+-------------+
| Rx plain       | accept     | accept     | accept      | drop        |
| (ACK|FIN|RST)  |            |            |             |             |
+----------------+------------+------------+-------------+-------------+
| Rx PSP (good)  | drop       | accept     | accept      | accept      |
+----------------+------------+------------+-------------+-------------+
| Rx PSP (bad    | drop       | drop       | drop        | drop        |
| crypt, !=SPI)  |            |            |             |             |
+----------------+------------+------------+-------------+-------------+
| Tx             | plain text | plain text | encrypted   | encrypted   |
|                |            |            | (excl. rtx) | (excl. rtx) |
+----------------+------------+------------+-------------+-------------+

To ensure that any data read from the socket after the ``tx-assoc``
call returns success has been authenticated, the kernel will scan the
receive and ofo queues of the socket at ``tx-assoc`` time. If any
enqueued packet was received in clear text, the Tx association will
fail, and the application should retry installing the Tx key after
draining the socket (this should not be necessary if both endpoints
are well behaved).

Because TCP sequence numbers are not integrity protected prior to
upgrading to PSP, it is possible that a MITM could offset sequence
numbers in a way that deletes a prefix of the PSP protected part of
the TCP stream. If userspace cares to mitigate this type of attack, a
special "start of PSP" message should be exchanged after ``tx-assoc``.

Upgrade to PSP must be done on established TCP connections.
``rx-assoc`` and ``tx-assoc`` will return ``-ENOTCONN`` if
``sk_state`` is not ``TCP_ESTABLISHED``.

The PSP assoc state of a socket is not reset when the connection is
torn down. ``connect()`` on a socket that has PSP assoc state will
return ``-EINVAL``.

Socket-less associations
~~~~~~~~~~~~~~~~~~~~~~~~

Associations which are not bound to a socket are managed with these
netlink commands:

- ``rx-spi-alloc`` allocates an Rx SPI and key, like ``rx-assoc`` but
  without a socket. It also creates an Rx association, which records the
  SPI, the version and the device key generation, and returns its ID.
  The key should be passed to the peer out of band, and installed with
  ``assoc-add``.
- ``assoc-add`` adds a Tx association with the peer's SPI and key, and
  returns its ID.
- ``assoc-del`` deletes an association. tc actions and packets which still
  reference it keep it alive. The device keeps decrypting the SPI of a
  deleted Rx association until its device key is rotated out: remove the
  decap rule to stop taking its packets.
- ``assoc-get`` reports associations, never their keys, and for Rx
  associations whether key rotation has made them stale.

The ``psp`` tc action attaches these associations to packets:

- ``psp encap assoc ID`` attaches a Tx association. The packet must then
  be transmitted on the main netdev of the association's PSP device, which
  encrypts it (``mirred egress redirect``). If the association is removed
  before transmit, or if the packet is transmitted on any other device,
  it will be dropped, rather than sent in the clear. Encap on ingress is
  hardware offload only.

- ``psp decap`` removes the PSP Rx state (the ``SKB_EXT_PSP`` extension and
  ``skb->decrypted``) of a decrypted packet, so that it can be forwarded. It
  takes no association. Its filter should match ``psp_spi``, ``psp_ver``
  and ``psp_dev``.

The flower classifier matches what a packet was decrypted with:
``psp_spi SPI[/MASK]``, ``psp_ver VERSION`` and ``psp_dev DEV_ID``, the
ID of the PSP device which decrypted it. These never match a clear text
packet, so ``psp_spi 0/0`` matches any packet decrypted with PSP.
Together they tie a decap rule to one Rx association.

Once the device key an SPI was created from has been rotated twice, that
association is considered stale. Unlike sockets, tc does not handle key
rotation. userspace should replace such rules before two rotations.

The device adds 40 bytes to each packet on transmit: the UDP and PSP
headers, and the ICV. The operator must size the MTU of the traffic
source for this. A packet which would not fit the PSP device's MTU once
encapsulated is dropped on transmit.

Rotation notifications
----------------------

The rotations of device key happen asynchronously and are usually
performed by management daemons, not under application control.
The PSP netlink family will generate a notification whenever keys
are rotated. The applications are expected to re-establish connections
before keys are rotated again.

Fragments
---------

PSP transport mode does not support IP fragments, either for sockets or
socket-less associations.

Statistics
----------

The ``get-stats`` netlink command reports the PSP device statistics:
kernel statistics (key rotations, stale events), and the device statistics
defined by the PSP specification. The device statistics count what the
device decrypts and encrypts.

The tc action counts the packets it processes and the ones it drops
(``tc -s``). Encapsulated packets dropped on transmit count in the
device's ``tx_dropped``. Drops are reported with these drop reasons:

- ``SKB_DROP_REASON_PSP_OUTPUT``: encap ran on ingress in software, or
  failed to parse the packet, or it is an IPv4 fragment or has IPv6
  extension headers, which transport mode doesn't support, or it is
  already encapsulated for a tunnel, already marked decrypted, or of a
  socket with its own encryption offload; or an encapsulated packet
  reached a device which isn't its PSP device's netdev, or its PSP
  device was unregistered while it was queued.
- ``SKB_DROP_REASON_PKT_TOO_BIG``: an encapsulated packet would not fit
  the device's MTU once the device adds the PSP encapsulation.

A packet encapsulated on egress which lost its association on the way is
dropped on transmit by ``sk_validate_xmit_skb()``, without a specific drop
reason.

Kernel implementation
=====================

Driver notes
------------

Drivers are expected to start with no PSP enabled (``psp-versions-ena``
in ``dev-get`` set to ``0``) whenever possible. The user space should
not depend on this behavior, as future extension may necessitate creation
of devices with PSP already enabled, nonetheless drivers should not enable
PSP by default. Enabling PSP should be the responsibility of the system
component which also takes care of key rotation.

Note that ``psp-versions-ena`` is expected to be used only for enabling
receive processing. The device is not expected to reject transmit requests
after ``psp-versions-ena`` has been disabled. User may also disable
``psp-versions-ena`` while there are active associations, which will
break all PSP Rx processing.

Drivers are expected to ensure that a device key is usable and secure
upon init, without explicit key rotation by the user space. It must be
possible to allocate working keys, and that no duplicate keys must be
generated. If the device allows the host to request the key for an
arbitrary SPI - driver should discard both device keys (rotate the
device key twice), to avoid potentially using a SPI+key which previous
OS instance already had access to.

Drivers must use ``psp_skb_get_assoc_rcu()`` to check if PSP Tx offload
was requested for given skb. The association comes from the skb's socket
or, for socket-less associations, from a ``METADATA_PSP`` dst which the
core keeps on the skb for the driver to use. On Rx drivers should
allocate and populate the ``SKB_EXT_PSP`` skb extension, and set the
``skb->decrypted`` bit to 1.

Kernel implementation notes
---------------------------

PSP implementation follows the TLS offload more closely than the IPsec
offload, with per-socket state (or per-association state, for
socket-less associations), and the use of ``skb->decrypted`` to prevent
clear text leaks.

PSP device is separate from netdev, to make it possible to "delegate"
PSP offload capabilities to software devices (e.g. ``veth``).
