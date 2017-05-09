# Copyright 2017 ETH Zurich
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
"""
:mod:`info` --- Extensions for AS Markings
==========================================
"""

# stdlib
import logging

# SCION
import proto.asm_exts_capnp as P
from lib.crypto.symcrypto import hash_func_for_type
from lib.crypto.trc import TRC
from lib.errors import SCIONSigVerError
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.types import ASMExtType, RoutingPolType


class RoutingPolicyExt(Cerealizable):
    NAME = "RoutingPolicyExt"
    EXT_TYPE = ASMExtType.ROUTING_POLICY
    P_CLS = P.RoutingPolicyExt
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, type_, if_, isd_ases):
        p = cls.P_CLS.new_message(set=True, polType=type_, ifID=if_)
        p.init("isdases", len(isd_ases))
        for i, isd_as in enumerate(isd_ases):
            p.isdases[i] = int(isd_as)
        return cls(p)

    def sig_pack3(self):
        """
        Pack for signing version 3 (defined by highest field number).
        """
        b = []
        if self.VER != 3:
            raise SCIONSigVerError("RoutingPolicyExt.sig_pack3 cannot support version %s", self.VER)
        b.append(self.p.set.to_bytes(1, 'big'))
        b.append(self.p.polType.to_bytes(1, 'big'))
        b.append(self.p.ifID.to_bytes(4, 'big'))
        for isd_as in self.p.isdases:
            b.append(isd_as.to_bytes(4, 'big'))
        return b"".join(b)

    def short_desc(self):
        a = []
        a.append("RoutingPolicyExt extension: Policy type: %s, Interface: %s, ASes:" %
                 (RoutingPolType.to_str(self.p.polType), self.p.ifID))
        for isd_as in self.p.isdases:
            a.append(" %s" % ISD_AS(isd_as))
        return "\n".join(a)


class ISDAnnouncementExt(Cerealizable):
    NAME = "ISDAnnouncementExt"
    EXT_TYPE = ASMExtType.ISD_ANNOUNCEMENT
    P_CLS = P.ISDAnnouncementExt
    VER = len(P_CLS.schema.fields) - 1

    def __init__(self, p):
        super().__init__(p)
        if not self.p.trc == b'':
            self.trc = TRC.from_raw(p.trc, lz4_=True)
        else:
            self.trc = None

    @classmethod
    def from_values(cls, hash_algorithm, trc_=None):
        hash_func = hash_func_for_type(hash_algorithm)
        hash_trc = hash_func(str(trc_).encode('utf-8'))
        if trc_ is None:
            p = cls.P_CLS.new_message(set=True, hashAlg=hash_algorithm, hashValue=hash_trc,
                                      trc=b'', currentlyRejected=False)
        else:
            p = cls.P_CLS.new_message(set=True, hashAlg=hash_algorithm, hashValue=hash_trc,
                                      trc=trc_.pack(lz4_=True), currentlyRejected=False)
        return cls(p)

    def sig_pack4(self):
        """
        Pack for signing version 4 (defined by highest field number).
        """
        if self.VER != 4:
            raise SCIONSigVerError("ISDAnnouncementExt.sig_pack4"
                                   " cannot support version %s", self.VER)
        b = []
        b.append(self.p.set.to_bytes(1, 'big'))
        b.append(self.p.hashAlg.to_bytes(2, 'big'))
        b.append(self.p.hashValue)
        b.append(self.p.trc)
        b.append(self.p.currentlyRejected.to_bytes(1, 'big'))
        return b''.join(b)

    def remove_trc(self):
        if self.trc:
            self.p.trc = ""
            ret = self.trc
            self.trc = None
            return ret
        else:
            logging.error('Tried removing a TRC from an announcement that'
                          'doesn\'t contain a TRC.')
            return None

    def add_trc(self, trc):
        if self.trc:
            logging.error('Tried adding a TRC to an announcement already'
                          ' containing a TRC.')
        else:
            self.p.trc = trc.pack(lz4_=True)
            self.trc = trc

    def make_final(self):
        self.trc.quarantine = False
        self.p.trc = self.trc.pack(lz4_=True)
        hash_func = hash_func_for_type(self.p.hashAlg)
        hash_trc = hash_func(str(self.trc).encode('utf-8'))
        self.p.hashValue = hash_trc

    def short_desc(self):
        if self.trc:
            return 'Announcing ISD %i.' % self.trc.isd
        else:
            return 'No TRC included.'


class AnnouncementRejectedExt(Cerealizable):
    NAME = "AnnouncementRejectedExt"
    EXT_TYPE = ASMExtType.ANNOUNCEMENT_REJECTED
    P_CLS = P.AnnouncementRejectedExt
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, indices):
        p = cls.P_CLS.new_message(set=True)
        p.init("indices", len(indices))
        for i, index in enumerate(indices):
            p.indices[i] = index
        return cls(p)

    def sig_pack1(self):
        """
        Pack for signing version 1 (defined by highest field number).
        """
        b = []
        if self.VER != 1:
            raise SCIONSigVerError("AnnouncementRejectedExt.sig_pack1"
                                   " cannot support version %s", self.VER)
        b.append(self.p.set.to_bytes(1, 'big'))
        for index in self.p.indices:
            b.append(index.to_bytes(4, 'big'))
        return b"".join(b)

    def short_desc(self):
        return 'Rejects announcements %s' % [i for i in self.p.indices]
