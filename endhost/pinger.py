#!/usr/bin/python3
# Copyright 2016 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Stdlib
import argparse
import logging
import socket
import time
import threading

# SCION
from endhost.sciond import SCIONDaemon
from lib.defines import GEN_PATH
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import HostAddrIPv4
from lib.packet.packet_base import PayloadRaw
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.socket import ReliableSocket
from lib.thread import kill_self, thread_safety_net
from lib.types import L4Proto
from lib.util import handle_signals


class Pinger:
    """Simple pinger application."""
    NEW_PING = 0
    RETRY = 1
    ERROR = 2

    def __init__(self, sd, addr, port, dst, dst_port, timeout=None,
                 qps=1.0):
        self.sd = sd
        self.addr = addr
        self.port = port
        self.dst = dst
        self.dst_port = dst_port
        self.qps = qps
        self.path = None
        self._switch_path = threading.Event()
        self.pinger_thread = threading.Thread(
            target=thread_safety_net, args=(self.send_pings,),
            name="Pinger.send_pings")
        self._stop = threading.Event()

        self.ping_pld = PayloadRaw(b"ping")
        self._last_ping_received = None

        self._timeout = timeout
        self.sock = self._create_socket(addr, port)
        assert self.sock

    def _create_socket(self, addr, port):
        sock = ReliableSocket(reg=(addr, port, True, None))
        sock.settimeout(self._timeout)
        return sock

    def _recv(self):
        try:
            packet = self.sock.recv()[0]
        except socket.timeout:
            return None
        return SCIONL4Packet(packet)

    def _send_pkt(self, spkt, next_=None):
        next_hop, port = next_ or self.sd.get_first_hop(spkt)
        assert next_hop is not None
        logging.debug("Sending (via %s:%s):\n%s", next_hop, port, spkt)
        self.sock.send(spkt.pack(), (next_hop, port))

    def _send(self):
        self._send_pkt(self._build_pkt(self.ping_pld))
        if self.path.interfaces:
            logging.debug("Interfaces: %s", ", ".join(
                ["%s:%s" % ifentry for ifentry in self.path.interfaces]))

    def _build_pkt(self, payload, path=None):
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, self.dst)
        l4_hdr = self._create_l4_hdr()
        if path is None:
            path = self.path
        extensions = []
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, extensions, l4_hdr)
        spkt.set_payload(payload)
        spkt.update()
        return spkt

    def _get_first_hop(self, spkt):
        return self.sd.get_first_hop(spkt)

    def _create_l4_hdr(self):
        return SCIONUDPHeader.from_values(
            self.addr, self.sock.port, self.dst, self.dst_port)

    def _get_path(self):
        """Requests paths to dst from sciond."""
        logging.debug("Sending PATH request for %s.", self.dst)
        for _ in range(20):
            paths = self.sd.get_paths(self.dst.isd_as)
            if paths:
                break
        else:
            logging.critical("Unable to get path directly from sciond")
            kill_self()
        self.path = paths[0]

    def _handle_packet(self, spkt):
        if spkt.l4_hdr.TYPE == L4Proto.SCMP:
            self._handle_scmp(spkt)
            return
        logging.debug("Received:\n%s", spkt.short_desc())
        payload = spkt.get_payload()
        if payload == self.ping_pld:
            if not self._last_ping_received:
                logging.info("Received first ping.")
                self._last_ping_received = time.time()
            else:
                now = time.time()
                time_since_last_ping = now - self._last_ping_received
                self._last_ping_received = now
                logging.info("Ping received. Time since last Ping: %.2fs" %
                             time_since_last_ping)
        else:
            logging.error("Unexpected payload received (%dB): %s" %
                          (len(payload, payload)))

    def _handle_scmp(self, spkt):
        start = time.time()
        scmp_hdr = spkt.l4_hdr
        spkt.parse_payload()
        if (scmp_hdr.class_ == SCMPClass.PATH and
                scmp_hdr.type == SCMPPathClass.REVOKED_IF):
            scmp_pld = spkt.get_payload()
            rev_info = RevocationInfo.from_raw(scmp_pld.info.rev_info)
            logging.info("Received revocation for IF %d." % rev_info.p.ifID)
            self.sd.handle_revocation(rev_info, None)
            self._switch_path.set()
        else:
            logging.error("Received SCMP error:\n%s", spkt)
        end = time.time()
        logging.info("Need %.3fs to process SCMP." % (end - start))

    def send_pings(self):
        """Main sending loop to continously send pings."""
        while not self._stop.isSet():
            if not self.path or self._switch_path.isSet():
                self._get_path()
                self._switch_path.clear()
            logging.info("Sending ping.")
            self._send()
            time.sleep(1 / self.qps)

    def run(self):
        """Main receving loop."""
        self.pinger_thread.start()
        try:
            while True:
                spkt = self._recv()
                if not spkt:
                    logging.info("Timeout waiting for response.")
                    continue
                self._handle_packet(spkt)
        finally:
            self.shutdown()

    def shutdown(self):
        self._stop.set()
        self.pinger_thread.join()
        self.sd.stop()
        self.sock.close()


def main():
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', default="INFO",
                        help='Console logging level (Default: %(default)s)')
    parser.add_argument('-s', '--source', required=True,
                        help="Source address:port pair.")
    parser.add_argument('-d', '--dest', required=True,
                        help="Destination address:port pair.")
    parser.add_argument('-sia', '--src-isd-as', required=True,
                        help="Source ISD-AS.")
    parser.add_argument('-dia', '--dest-isd-as', required=True,
                        help="Destination ISD-AS.")
    parser.add_argument('--qps', default=1.0, type=float,
                        help="Pings per second.")
    args = parser.parse_args()
    # Process cmdline arguments.
    try:
        src_addr, src_port = args.source.split(':')
        src_port = int(src_port)
    except ValueError:
        src_addr = args.source
        src_port = 37000
    try:
        dst_addr, dst_port = args.dest.split(':')
        dst_port = int(dst_port)
    except ValueError:
        dst_addr = args.dest
        dst_port = 37001
    src_isd_as = ISD_AS(args.src_isd_as)
    dst_isd_as = ISD_AS(args.dest_isd_as)
    src_addr = SCIONAddr.from_values(src_isd_as, HostAddrIPv4(src_addr))
    dst_addr = SCIONAddr.from_values(dst_isd_as, HostAddrIPv4(dst_addr))
    init_logging("logs/pinger-%s.log" %
                 src_isd_as, console_level=args.loglevel)
    # Setup the SCION daemon.
    conf_dir = "%s/ISD%d/AS%d/endhost" % (GEN_PATH,
                                          src_isd_as[0], src_isd_as[1])
    daemon = SCIONDaemon.start(conf_dir, src_addr.host)
    # Start pinger.
    pinger = Pinger(daemon, src_addr, src_port,
                    dst_addr, dst_port, qps=args.qps)
    pinger.run()


if __name__ == "__main__":
    main_wrapper(main)
