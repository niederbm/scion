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
:mod: coordinator --- ISD coordination utilities
================================================
"""

# Stdlib
import logging
import os
import json
from json.decoder import JSONDecodeError
from copy import deepcopy

# External packages
from external.expiring_dict import ExpiringDict

# SCION
from lib.crypto.trc import TRC
from lib.defines import ISD_COORDINATION_CONFIG
from lib.errors import SCIONJSONError, SCIONKeyError, \
    SCIONTypeError, SCIONValueError, SCIONIndexError, SCIONBaseError
from lib.packet.cert_mgmt import TRCReply
from lib.packet.asm_exts import ISDAnnouncementExt, AnnouncementRejectedExt
from lib.types import ASMExtType, HashType
from lib.util import read_file, SCIONTime


class ISDCoordinator(object):
    """
    Class that serves as utility for adding new ISDs, removing old ISDs and
    logging/resolving coordination conflicts
    """

    # Maximum length of existing_isds and blacklist, as 4096 is the maximum number of ISDs globally
    MAX_LENGTH = 4096

    # Conversion factor from days to seconds
    DAYS_TO_SECONDS = 24 * 60 * 60

    # Policies for automated conflict resolution
    MAJORITY_BASED = 0
    TRUST_BASED = 1

    # Policies for announcement rejection
    IMITATE_PREVIOUS = 0
    IGNORE = 1

    # Maps configuration fields to their types
    FIELDS_MAP = {
        'polling_dir': str,
        'min_days': float,
        'max_days': float,
        'max_announcements': int,
        'conflict_resolution_policy': int,
        'rejection_policy': int
    }

    # Categories that the coordinator recognizes announcements as
    ACCEPTED_FINAL = 0
    ACCEPTED_KNOWN = 1
    EARLY = 2
    KNOWN_EARLY = 3
    REJECTED_CONFLICT = 4
    REJECTED_UNKNOWN = 5
    REJECTED_INVALID = 6
    REJECTED_VER_NONZERO = 7
    REJECTED_TRC_INCONSISTENT = 8
    TOO_MANY_ANNOUNCEMENTS = 9
    OWN_ANNOUNCEMENT = 10
    CLASHES_OWN = 11

    # TRC "version" for which this class's compare function was written
    # defined by the fields map of the TRC class
    TRC_FIELDS_MAP = {
        'ISDID': ("isd", int),
        'Description': ("description", str),
        'Version': ("version", int),
        'CreationTime': ("time", int),
        'CoreCAs': ("core_ases", dict),
        'RootCAs': ("root_cas", dict),
        'PKILogs': ("pki_logs", dict),
        'QuorumEEPKI': ("quorum_eepki", int),
        'RootRainsKey': ("root_rains_key", bytes),
        'QuorumOwnTRC': ("quorum_own_trc", int),
        'QuorumCAs': ("quorum_cas", int),
        'Quarantine': ("quarantine", bool),
        'Signatures': ("signatures", dict),
        'GracePeriod': ("grace_period", int),
    }
    TRC_NOCOMP_FIELDS = ['Version', 'CreationTime', 'PKILogs', 'Quarantine', 'Signatures']

    def __init__(self, config_file_path, trust_store,
                 certificate_server_getter, meta_sender, isd_as, propagation_time):

        # These are set to achieve a higher pylint rating.
        self.polling_dir = ''
        self.min_days = 0
        self.max_days = 0
        self.max_announcements = 0
        self.conflict_resolution_policy = 0
        self.rejection_policy = 0
        self._certificate_server_getter = certificate_server_getter
        self._meta_sender = meta_sender
        self.isd_as = isd_as
        self.propagation_time = propagation_time
        self.currently_rejecting = {}

        # Read parameters from config file
        config_file = os.path.join(config_file_path, ISD_COORDINATION_CONFIG)
        config_dict = json.loads(read_file(config_file))
        for field_name, type_ in self.FIELDS_MAP.items():
            val = config_dict[field_name]
            if type_ in (int,):
                val = int(val)
            elif type_ in (float,):
                val = float(val)
            setattr(self, field_name, val)

        self.trust_store = trust_store
        self.announcements_list = []
        self.downstream_announcements = []
        self.downstream_iterator = iter(self.downstream_announcements)
        self.announcements_iterator = iter(self.announcements_list)
        self.unresolved_final_announcements = FinalAnnouncementsList(self)

        # The trust list is initialized in the order TrustStore.get_trcs() returns the ISDs.
        self.trust_list = [trust_trc.isd for trust_trc in trust_store.get_trcs()]
        if not self.trust_list:
            logging.warning('Initialized ISDCoordinator with empty trust list. This may '
                            'result in an infinite loop when attempting '
                            'to automatically resolve conflicts.')

        self.blacklist = Blacklist(self.max_days * self.DAYS_TO_SECONDS, self)

        # Set up ExpiringDict containers for existing ISDs and check if the list is unique
        self.early_announcements = {}
        seen_isds = set()
        for isd in self.trust_list:
            if isd in seen_isds or seen_isds.add(isd):
                logging.warning("ISD %d has duplicate entries.", isd)
            else:
                self.early_announcements[isd] = \
                    ExpiringDict(self.MAX_LENGTH, self.max_days * self.DAYS_TO_SECONDS)

        # Set up dict of existing ISDs from trust store
        trc_list = trust_store.get_trcs()
        logging.debug('')
        self.existing_isds = {}
        for trc in trc_list:
            self.existing_isds[trc.isd] = trc

    def add_announcement_core(self, asm):
        self._check_new_announcements(HashType.SHA256)
        for ann_time in self.announcements_list:
            if int(SCIONTime.get_time()) - ann_time[1] < self.min_days * self.DAYS_TO_SECONDS:
                asm.add_ext(deepcopy(ann_time[0]), ASMExtType.ISD_ANNOUNCEMENT)
            elif int(SCIONTime.get_time()) - ann_time[1] < self.max_days * self.DAYS_TO_SECONDS:
                if ann_time[0].trc.quarantine:
                    ann_time[0].make_final()
                    ann_time[1] = int(SCIONTime.get_time()) - self.min_days * self.DAYS_TO_SECONDS
                    asm.add_ext(deepcopy(ann_time[0]), ASMExtType.ISD_ANNOUNCEMENT)
                else:
                    asm.add_ext(deepcopy(ann_time[0]), ASMExtType.ISD_ANNOUNCEMENT)
            else:
                self.announcements_list.remove(ann_time)

    def add_announcement_downstream(self, asm):
        for ann_time in self.downstream_announcements:
            if int(SCIONTime.get_time()) - ann_time[1] < \
                            (self.max_days - self.min_days) * self.DAYS_TO_SECONDS:

                asm.add_ext(deepcopy(ann_time[0]), ASMExtType.ISD_ANNOUNCEMENT)
            else:
                self.downstream_announcements.remove(ann_time)

    def add_announcement_rejection(self, pcb, asm):
        """
        Checks whether this BS has reason to reject the PCB's announcement
         extension if one is present.
        """
        reject = []
        for i, curr_asm in enumerate(pcb.iter_asms()):
            if i == 0:
                try:
                    next(curr_asm.isd_announcement_exts_iter())
                except StopIteration:
                    return
                for j, ann in enumerate(curr_asm.isd_announcement_exts_iter()):
                    if ann.p.currentlyRejected:
                        ann.p.currentlyRejected = False
                        reject.append(j)
            else:
                rejection_ext = curr_asm.announcement_rejected_ext()
                if rejection_ext:
                    for index in rejection_ext.p.indices:
                        self.currently_rejecting.setdefault(index, [])
                        self.currently_rejecting[index].append(curr_asm.isd_as()[0])
                        if index not in reject and self._rejection_policy_check(curr_asm):
                            reject.append(index)

        if reject:
            asm.add_ext(AnnouncementRejectedExt.from_values(reject),
                        ASMExtType.ANNOUNCEMENT_REJECTED)

        self.currently_rejecting = {}

    def add_downstream_announcement(self, trc, hash_type):
        self._remove_expired()
        self.downstream_announcements.append(Pair(self._create_announcement(trc, hash_type),
                                                  int(SCIONTime.get_time())))

    def handle_announcement(self, ext, announcing_isd):
        """
        Handles an incoming announcement according to whether it is early
        or final, and depending on blacklist status and how many announcements
        originating from the announcing ISD are currently stored.

        :param ext: The announcement to be processed.
        :param announcing_isd: The ID of the ISD that originated this announcement.
        :return: Returns category the current announcement was put in
        """
        self._remove_expired()
        trc = ext.trc
        if announcing_isd not in self.existing_isds:
            logging.warning('Received an announcement from unknown ISD%i: '
                            'Announced ISD%s with description "%s"'
                            % (announcing_isd, trc.isd, trc.description))
            return self.REJECTED_UNKNOWN
        if not trc.version == 0:
            ext.p.currentlyRejected = True
            return self.REJECTED_VER_NONZERO
        # TODO: verify function is broken, uncomment when it's fixed
        # if not trc.verify(trc):
            # # TRC is not internally consistent
            # ext.p.currentlyRejected = True
            # return self.REJECTED_TRC_INCONSISTENT
        # Checks if it is a known early announcement
        for ex_trc in list(self.existing_isds.values()):
            if self._compare_early_final(trc, ex_trc):
                return self.ACCEPTED_KNOWN
        if trc.quarantine:
            if trc.isd in [anntime[0].trc.isd for anntime in self.announcements_list]:
                # Collision with an announcement we are making, reject
                return self.OWN_ANNOUNCEMENT
            for own_ann in self.announcements_list:
                if self._compare_early_final(trc, own_ann):
                    return self.OWN_ANNOUNCEMENT
                elif announcing_isd == self.isd_as(0):
                    return self.CLASHES_OWN
            # Is the announcement already stored and not expired?
            if trc not in self.early_announcements[announcing_isd].values():
                for i in range(0, self.max_announcements):
                    # Checks if any free counters are vacant
                    if self.early_announcements[announcing_isd].ttl(i) is None:
                        self.early_announcements[announcing_isd][i] = trc
                        self.unresolved_final_announcements.check_conflicts()
                        return self.EARLY
                return self.TOO_MANY_ANNOUNCEMENTS
            return self.KNOWN_EARLY

        else:  # This is a final announcement
            if self._is_valid(trc, announcing_isd):
                if self.unresolved_final_announcements.contains_soft(trc):
                    return
                conflicting_trcs, announcers_list = self._get_conflicting_trcs(trc, announcing_isd)
                if not conflicting_trcs:
                    # Corresponding early was not found
                    return
                if not len(conflicting_trcs) == 1:
                    logging.warning('A final announcement for ISD%i '
                                    'has an ID collision with another'
                                    'early announcement. This should be'
                                    'resolved by an administrator.')
                    # Get ttl of corresponding early announcement
                    index = [key for key, announcement in
                             self.early_announcements[announcing_isd].items()
                             if self._compare_early_final(trc, announcement)].pop(0)
                    ttl = self.early_announcements[announcing_isd].ttl(index)
                    if ttl:
                        self.unresolved_final_announcements.append(
                            (trc, announcing_isd, int(SCIONTime.get_time()) +
                             ttl - 3 * self.propagation_time))
                    return

                if not self.blacklist.contains_soft(trc):
                    self._add_isd(trc)
                    return self.ACCEPTED_FINAL
                ext.p.currentlyRejected = True
                return self.REJECTED_CONFLICT
            else:
                ext.p.currentlyRejected = True
                return self.REJECTED_INVALID

    def update_trust_list(self, neighbor):
        """
        Updates trust list from trust store and moves the
        neighbor to the start of the list.

        :param neighbor: ID to be moved
        """
        trust_set = set(self.trust_list)
        store_set = set([trust_trc.isd for trust_trc in self.trust_store.get_trcs()])
        newcomers = store_set - trust_set
        stale = trust_set - store_set
        for isd in stale:
            self.trust_list.remove(isd)
        self.trust_list += list(newcomers)
        try:
            self.trust_list.remove(neighbor)
        except ValueError:
            logging.warning('Found previously unknown neighbor ISD')
            return
        self.trust_list.insert(0, neighbor)
        try:
            self.trust_list.remove(self.isd_as(0))
        except ValueError:
            logging.warning('Self not in trust list')
        self.trust_list.insert(0, self.isd_as(0))

    def _add_isd(self, trc):
        logging.info('Added ISD%i with desc %s' % (trc.isd, trc.description))
        self.existing_isds[trc.isd] = trc
        self.trust_store.add_trc(trc)
        self.trust_list.append(trc.isd)
        self.early_announcements[trc.isd] = \
            ExpiringDict(self.MAX_LENGTH, self.max_days * self.DAYS_TO_SECONDS)
        meta = self._certificate_server_getter()
        self._meta_sender(TRCReply.from_values(trc), meta)
        self.add_downstream_announcement(trc, HashType.SHA256)

    def _check_new_announcements(self, hash_type):
        """
        Checks the directory specified in polling_dir for new TRCs to be announced.
        If a file is found and a TRC is built from it, the file will be deleted.

        :param hash_type: The hash function to be used in extension creation, defaults to SHA256.
        :return: Returns an announcement extension containing the new TRC
         if a valid file was found in the directory and None otherwise.
        """
        file_list = os.listdir(self.polling_dir)
        # Remove hidden files
        file_list = [item for item in file_list if not item.startswith('.')]

        for trc_file_name in file_list:
            trc_file_path = os.path.join(self.polling_dir, trc_file_name)
            trc_file = read_file(trc_file_path)
            core_trc = None
            try:
                core_trc = TRC.from_raw(trc_file)
                core_anntime = Pair(self._create_announcement(core_trc, hash_type),
                                    int(SCIONTime.get_time()))
                self.announcements_list.append(core_anntime)
                # Immediately add the newcomer to known ISDs
                downstream_trc = deepcopy(core_trc)
                downstream_trc.quarantine = False
                self.existing_isds[downstream_trc.isd] = downstream_trc
                self.trust_store.add_trc(downstream_trc)
                if downstream_trc.isd not in self.trust_list:
                    self.trust_list.append(downstream_trc.isd)
                if downstream_trc.isd not in self.early_announcements:
                    self.early_announcements[downstream_trc.isd] = \
                        ExpiringDict(self.MAX_LENGTH, self.max_days * self.DAYS_TO_SECONDS)
                downstream_anntime = Pair(self._create_announcement(downstream_trc, hash_type),
                                          int(SCIONTime.get_time()))
                self.downstream_announcements.append(downstream_anntime)
                # Inform certificate server
                meta = self._certificate_server_getter()
                self._meta_sender(TRCReply.from_values(downstream_trc), meta)
                logging.info('Created ann for ISD%s at %s' % core_anntime[0].trc.isd)
                if len(self.announcements_list) > self.max_announcements:
                    logging.warning('Disseminating more announcements than accepted by'
                                    'max_Announcements')
            except KeyError as error:
                raise SCIONKeyError('Error while reading a TRC file. '
                                    'Probable cause is an error with key %s.', error.args[0])
            except JSONDecodeError:
                raise SCIONJSONError('Error while reading a TRC file. '
                                     'Probable cause is incorrect JSON formatting.')
            except ValueError:
                raise SCIONValueError('Error while reading a TRC file. '
                                      'Probable cause is an incorrect value for a field.')
            except TypeError:
                SCIONTypeError('Error while reading a TRC file. '
                               'Probable cause is an erroneous type of a field.')
            if core_trc:
                # Announcement was created, delete the file
                os.remove(trc_file_path)

                logging.info('Created the announcement for ISD%i and deleted the'
                             ' corresponding file.' % core_trc.isd)

    def _compare_early_final(self, first, second):
        # Only compare relevant details of the TRCs
        if self.TRC_FIELDS_MAP == TRC.FIELDS_MAP:
            copy_of_first = deepcopy(first)
            copy_of_second = deepcopy(second)
            copy_of_second.quarantine = copy_of_first.quarantine
            for item in self.TRC_NOCOMP_FIELDS:
                setattr(copy_of_first, self.TRC_FIELDS_MAP[item][0],
                        getattr(copy_of_second, self.TRC_FIELDS_MAP[item][0]))
            return copy_of_first == copy_of_second
        else:
            raise SCIONBaseError('Tried to compare TRCs with version unfit for this method.')

    @staticmethod
    def _create_announcement(trc, hash_type):
        """
        Creates an announcement extension from a TRC.
        """

        return ISDAnnouncementExt.from_values(hash_type, trc)

    def _get_announcement(self, hash_type=0):
        """
        Returns announcements in round-robin fashion if any are present.
        If an announcement has passed the min_days period, it is
        transformed into a final announcement.
        :return: An announcement extension or None
        """
        self._check_new_announcements(hash_type)
        if self.announcements_list:
            try:
                ann_time = next(self.announcements_iterator)
            except StopIteration:
                self.announcements_iterator = iter(self.announcements_list)
                ann_time = next(self.announcements_iterator)
            if int(SCIONTime.get_time()) - ann_time[1] < self.min_days * self.DAYS_TO_SECONDS:
                return deepcopy(ann_time[0])
            elif int(SCIONTime.get_time()) - ann_time[1] < self.max_days * self.DAYS_TO_SECONDS:
                if ann_time[0].trc.quarantine:
                    ann_time[0].make_final()
                    ann_time[1] = int(SCIONTime.get_time()) - self.min_days * self.DAYS_TO_SECONDS
                    return deepcopy(ann_time[0])
                else:
                    return deepcopy(ann_time[0])
            else:
                self.announcements_list.remove(ann_time)
                return self._get_announcement()

        else:
            return None

    def _get_conflicting_trcs(self, trc, announcing_isd):
        """
        Checks whether trc has an id conflicting (i.e. identical) with the
        id of another announcement.

        :param trc: TRC whose id are checked.
        :return: Returns list of conflicting trcs/early announcements.
        """
        contestants = []
        announcers = {}
        early_trc = deepcopy(trc)
        early_trc.quarantine = True
        for isd in self.early_announcements:
            if isd == announcing_isd:
                for announcement in self.early_announcements[isd].values():
                    if self.blacklist.contains_soft(announcement):
                        continue
                    if announcement.isd == trc.isd:
                        if self._compare_early_final(announcement, trc):
                            # Corresponding early announcement, add to list
                            contestants.append((announcement, isd))
                            announcers.setdefault(announcement.pack(True), [])
                            announcers[announcement.pack(True)].append(isd)
                        else:
                            logging.warning('ISD%i announced multiple newcomer ISDs with'
                                            ' matching ids' % isd)
                            contestants.append((announcement, isd))
                            announcers.setdefault(announcement.pack(True), [])
                            announcers[announcement.pack(True)].append(isd)

            else:
                for announcement in self.early_announcements[isd].values():
                    if self.blacklist.contains_soft(announcement):
                        continue
                    if announcement.isd == trc.isd:
                        if self._compare_early_final(announcement, trc):
                            # Same announcement from another announcer,
                            # no conflict but add announcer to dict
                            announcers.setdefault(early_trc.pack(True), [])
                            announcers[early_trc.pack(True)].append(isd)
                        else:
                            if not announcement.pack(True) in announcers.keys():
                                contestants.append((announcement, isd))
                            announcers.setdefault(announcement.pack(True), [])
                            announcers[announcement.pack(True)].append(isd)

        return contestants, announcers

    def _get_downstream_announcement(self):
        if self.downstream_announcements:
            try:
                ann_time = next(self.downstream_iterator)
            except StopIteration:
                self.downstream_iterator = iter(self.downstream_announcements)
                ann_time = next(self.downstream_iterator)
            if int(SCIONTime.get_time()) - ann_time[1] > self.max_days * self.DAYS_TO_SECONDS:
                return deepcopy(ann_time[0])
            else:
                self.downstream_announcements.remove(ann_time)
                return self._get_downstream_announcement()
        else:
            return None

    def _is_valid(self, trc, announcing_isd):
        """
        Checks a final announcement for validity.

        :param trc: The TRC of the announcement in question.
        :return: Returns true iff the final announcement is valid.
        """

        for blacklisted_announcement in self.blacklist:
            if self._compare_early_final(blacklisted_announcement, trc):
                logging.info('Received blacklisted announcement for'
                             ' ISD%i from ISD%i' % (trc.isd, announcing_isd))
                return False

        # Does the ISD have an ID clash?
        for isd in self.existing_isds:
            if isd == trc.isd and \
                    not self._compare_early_final(trc, self.existing_isds[isd]):
                logging.info('Received a final announcement'
                             ' that clashes with the known ISD%i\n' % isd)
                return False

        # Is there a corresponding early announcement that has passed the min_days period?
        familiar_and_expired = False
        max_ttl = (self.max_days - self.min_days) * self.DAYS_TO_SECONDS
        for key, announcement in self.early_announcements[announcing_isd].items():
            try:
                if self._compare_early_final(announcement, trc) \
                        and self.early_announcements[announcing_isd].ttl(key) <= max_ttl:
                    familiar_and_expired = True
            except TypeError:
                # Timer ran out,we compared to None.
                pass

        return familiar_and_expired

    @staticmethod
    def _list_of_announcers(trc, announcers_list):
        """
        Collects all ISD ids of ISDs that have announced trc.

        :param trc: TRC for which the announcing ISDs are collected.
        :return: Returns a list of ids of ISDs that announced trc.
        """
        return announcers_list[trc.pack(True)]

    @staticmethod
    def _number_of_announcers(trc, announcers_list):
        """
        Counts the number of ISDs that currently have correctly announced trc.

        :param trc: TRC to have the announcements counted for.
        :return: Returns the number of ISDs that currently have correctly announced trc.
        """
        return len(announcers_list[trc.pack(True)])

    def _rejection_policy_check(self, asm):
        if self.rejection_policy == self.IMITATE_PREVIOUS:
            return True
        elif self.rejection_policy == self.IGNORE:
            return False
        else:
            raise SCIONValueError('Unknown rejection policy')

    def _remove_expired(self):
        # TODO: (niederbm) uncomment after PR 1144 is merged
        for isd in list(self.existing_isds):
            # if int(SCIONTime.get_time()) > self.existing_isds[isd].exp_time:
                try:
                    pass
                    # self.existing_isds.pop(isd)
                except KeyError:
                    pass

    def _resolve_conflicts(self, contestants, announcer_list, conflict_resolution_policy):
        """
        Automatically resolves ID conflicts of trc based on the
        given conflict_resolution_policy.

        :param contestants: The TRCs that have ID collisions.
        :param announcer_list: Dict of lists of announcers for every contestant.
        Keys are the root RAINS keys
        :param conflict_resolution_policy: The policy on which resolution should be based.
        :return: Does not return anything.
        """
        if conflict_resolution_policy == self.MAJORITY_BASED:
            # Find TRC with the conflicting ID that was announced by most ISDs
            max_announcers = 0
            best_trc = None
            best_announcer = None
            single_max = False
            for announcement, announcer in contestants:
                current_announcers = self._number_of_announcers(announcement, announcer_list)
                if current_announcers > max_announcers:
                    single_max = True
                    best_trc = announcement
                    best_announcer = announcer
                    max_announcers = current_announcers
                elif current_announcers == max_announcers:
                    if not self._compare_early_final(best_trc, announcement):
                        single_max = False
            if single_max:
                # Signal that the best_trc has no longer any conflicts
                # and blacklist all other announcements
                contestants.remove((best_trc, best_announcer))
                for blacklisted, announcer in contestants:
                    if not self._compare_early_final(best_trc, blacklisted):
                        logging.warning('An announcement for ISD%i by ISD%i was'
                                        'blacklisted.' % (blacklisted.isd, announcer))
                        self.blacklist.append(blacklisted)
            else:
                # Try with the trust list policy
                logging.info('Majority-based conflict resolution failed, resorting to'
                             'trust-based.')
                self._resolve_conflicts(contestants, announcer_list, self.TRUST_BASED)
        elif conflict_resolution_policy == self.TRUST_BASED:
            # Find TRC with the conflicting ID that was announced by the most trusted ISD.
            # The trust list is assumed to be in descending order from most to least trusted.

            # Initialized so it can be accessed outside the loop even if list_of_announcers is empty
            contestant = None
            announcer = None
            for isd in self.trust_list:
                for contestant, announcer in contestants:
                    if isd in self._list_of_announcers(contestant, announcer_list):
                        # Found the most trusted announcement, blacklist others
                        contestants.remove((contestant, announcer))
                        for blacklisted, announcer_b in contestants:
                            logging.warning('An announcement for ISD%i by ISD%i was'
                                            'blacklisted.' % (blacklisted.isd, announcer_b))
                            self.blacklist.append(blacklisted)
                        break
                # If contestant was removed, we can stop looping
                if (contestant, announcer) not in contestants:
                    break


class Pair:
    NAME = "Pair"

    def __init__(self, first, second):
        self._f = first
        self._s = second

    def __getitem__(self, item):
        if item == 0:
            return self._f
        elif item == 1:
            return self._s
        else:
            raise SCIONIndexError("Invalid index used on %s object: %s" % (
                (self.NAME, item)))

    def __setitem__(self, key, value):
        if key == 0:
            self._f = value
        elif key == 1:
            self._s = value
        else:
            raise SCIONIndexError("Invalid index used on %s object: %s" % (
                (self.NAME, key)))


class Blacklist:
    def __init__(self, max_time, coordinator):
        self.limit = max_time
        self.trcs = []
        self.timers = []
        self._counter = 0
        self.coordinator = coordinator

    def append(self, new_trc):
        self.trcs.append(new_trc)
        self.timers.append(int(SCIONTime.get_time()))

    def contains_soft(self, trc):
        for idx, entry in enumerate(self.trcs):
            if self.coordinator._compare_early_final(trc, entry):
                if int(SCIONTime.get_time()) - self.timers[idx] > self.limit:
                    self.trcs.pop(idx)
                    self.timers.pop(idx)
                    return self.contains_soft(trc)
                else:
                    return True
        return False

    def __contains__(self, trc):
        if trc in self.trcs:
            idx = self.trcs.index(trc)
            if int(SCIONTime.get_time()) - self.timers[idx] > self.limit:
                self.trcs.pop(idx)
                self.timers.pop(idx)
                return trc in self
            else:
                return True
        else:
            return False

    def __iter__(self):
        self._counter = 0
        return self

    def __next__(self):
        if (not self.trcs) or self._counter > len(self.trcs) - 1:
            raise StopIteration
        if int(SCIONTime.get_time()) - self.timers[self._counter] > self.limit:
            self.trcs.pop(self._counter)
            self.timers.pop(self._counter)
            return next(self)
        else:
            self._counter += 1
            return self.trcs[self._counter - 1]


class FinalAnnouncementsList:
    # The triples consist of TRC, announcer and expiration time (in that order)

    def __init__(self, coordinator):
        self._list = []
        self.coordinator = coordinator
        self._counter = 0

    def __iter__(self):
        self._counter = 0
        return self

    def __next__(self):
        if (not self._list) or self._counter > len(self._list) - 1:
            raise StopIteration
        else:
            self._counter += 1
            return self._list[self._counter - 1]

    def append(self, triple):
        self._list.append(triple)

    def pop(self, idx):
        self._list.pop(idx)

    def contains_soft(self, trc):
        for idx, entry in enumerate(self._list):
            if self.coordinator._compare_early_final(trc, entry[0]):
                return True
        return False

    def _purge_isd(self, isd):
        purge_list = []
        for final_announcement in self._list:
            if isd == final_announcement[0].isd:
                purge_list.append(final_announcement)
        for item in purge_list:
            self._list.remove(item)

    def check_conflicts(self):
        for triple in self._list:
            if self.coordinator.blacklist.contains_soft(triple[0]):
                # self._list.remove(triple)
                continue
            conflicting_trcs, announcers_list = \
                self.coordinator._get_conflicting_trcs(triple[0], triple[1])
            if not conflicting_trcs:
                # Corresponding early was not found, hence the announcement is expired
                pass
            if len(conflicting_trcs) == 1:
                # No conflicts, accept this announcement and remove it from this list
                self.coordinator._add_isd(triple[0])
                self._purge_isd(triple[0].isd)

            else:
                if int(SCIONTime.get_time()) > triple[2]:
                    # Announcement has expired without having it's conflicts resolved
                    while True:
                        conflicting_trcs, announcers_list = \
                            self.coordinator._get_conflicting_trcs(triple[0], triple[1])
                        if not conflicting_trcs:
                            # Corresponding early was not found
                            return
                        if len(conflicting_trcs) == 1:
                            break

                        self.coordinator._resolve_conflicts(
                            conflicting_trcs,
                            announcers_list,
                            self.coordinator.conflict_resolution_policy)

                    if not self.coordinator.blacklist.contains_soft(triple[0]):
                        self.coordinator._add_isd(triple[0])
                        self._purge_isd(triple[0].isd)

                else:
                    # Announcement still has conflicts but didn't expire yet, nothing to do
                    pass
