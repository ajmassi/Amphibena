import logging
import multiprocessing
import warnings

from cryptography.utils import CryptographyDeprecationWarning

# Suppresses warning from cryptography package (imported by scapy for tls support)
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import netfilterqueue
from scapy.layers.inet import IP
from scapy.layers.tls.all import *

from amphivena import playbook_utils

log = logging.getLogger(__name__)


class PacketProcessor:
    def __init__(self, playbook_file_path):
        """
        Initialize PacketProcessor, load playbook data and gather basic config for execution

        :param playbook_file_path: string representation of playbook file path.
        :return: PacketProcessor
        :raise PlaybookValidationError: Raised during playbook validation.
        """
        try:
            self._playbook_data = playbook_utils.load(playbook_file_path)
        except playbook_utils.PlaybookValidationError as e:
            raise e

        self._playbook_is_ordered = self._playbook_data.get("isOrdered")
        self._current_step = 1
        self._step_count = len(self._playbook_data.get("instructions"))
        self.proc = None

    def start(self):
        """
        Spin off PacketProcessor process and begin execution.

        :return: multiprocessing.Process
        """
        self.proc = multiprocessing.Process(target=self._examine_packets)
        self.proc.start()
        return self.proc

    def stop(self):
        """
        Stop PacketProcessor process execution.
        """
        if self.proc._closed is False:
            self.proc.terminate()
            self.proc.join()
            self.proc.close()

    def _examine_packets(self):
        """
        Pull packets from NFQueue for processing.

        :raise KeyboardInterrupt:
        """
        nfqueue = netfilterqueue.NetfilterQueue()
        nfqueue.bind(1, self._process)
        try:
            log.info("Starting nfqueue")
            nfqueue.run()
        except KeyboardInterrupt:
            log.warning("Caught keyboard interrupt")

        nfqueue.unbind()

    def _process(self, pkt):
        """
        Evaluate the current Packet, determine what playbook steps will be applied to it, call operations as needed.

        :param pkt: NetfilterQueue.Packet
        """
        scapy_packet = IP(pkt.get_payload())

        instr_list = self._assemble_instruction_list(scapy_packet)
        log.info("Starting processing")
        for instruction in instr_list:
            try:
                if instruction["operation"] == "drop":
                    self._drop(pkt)
                    return
                elif instruction["operation"] == "edit":
                    self._edit_packet(scapy_packet, instruction)
                else:
                    log.error(
                        f"Unknown packet operation '{instruction.get('operation')}'"
                    )
            except KeyError:
                log.error("Packet operation [drop, edit] not defined.")

        pkt.set_payload(scapy_packet.build())
        self._finalize(pkt)

    def _assemble_instruction_list(self, scapy_packet):
        """
        Evaluate how many, if any, playbook instruction(s) will be executed against scapy_packet.

        :param scapy_packet: Scapy.Packet - parsed from NFQueue
        :return: list of instructions from playbook to be executed against scapy_packet
        """
        instr_list = self._playbook_data.get("instructions")
        # If instructions are to be executed in order, assign next step
        if self._playbook_is_ordered:
            if self._current_step > self._step_count:
                log.error("No packet operations left!")
                return None

            instr_list = [
                self._playbook_data.get("instructions").get(str(self._current_step))
            ]

        # Remove instructions that do not map to current packet
        for i in instr_list:
            matching = self._analyze_packet(scapy_packet, i)
            if not matching:
                instr_list.remove(i)

        return instr_list

    @staticmethod
    def _analyze_packet(scapy_packet, instruction):
        """
        Evaluate scapy_packet against the current instruction's conditions to determine if the given step will execute.

        :param scapy_packet: Scapy.Packet - parsed from NFQueue
        :param instruction: dict - playbook instruction
        :return: boolean
        """
        # If we have conditions, we will check the scapy_packet against them
        if conditions := instruction.get("conditions"):
            for c in conditions:
                layer = c.get("layer")
                # Make sure the scapy_packet has the specified layer
                if scapy_packet.haslayer(layer):
                    try:
                        packet_field = getattr(scapy_packet.getlayer(layer), c["field"])
                        # TODOish An assumption is made here that we want to attempt type-sameness, but we might want a
                        #  mode that throws caution to the wind
                        value = type(packet_field)(c["value"])

                        if not getattr(scapy_packet.getlayer(layer), c["field"]) == value:
                            return False
                    except AttributeError:
                        log.warning(f"Packet does not contain field {c['field']}")
                        return False
                else:
                    log.warning(f"Packet does not contain layer {layer}")
                    return False
        return True

    @staticmethod
    def _edit_packet(scapy_packet, instruction):
        """
        Apply changes to packet as defined by playbook instruction's actions.

        :param scapy_packet: Scapy.Packet - parsed from NFQueue
        :param instruction: dict - playbook instruction
        """
        if actions := instruction.get("actions"):
            for a in actions:
                layer = a.get("layer")
                # Make sure the scapy_packet has the specified layer
                if scapy_packet.haslayer(layer):
                    if a.get("type") == "modify":
                        packet_field = getattr(scapy_packet.getlayer(layer), a["field"])
                        value = type(packet_field)(a["value"])

                        setattr(
                            scapy_packet.getlayer(instruction.get("layer")),
                            a.get("field"),
                            value,
                        )
                else:
                    log.warning(f"Packet does not contain layer {layer}")
        else:
            log.error(f"No actions set for instruction:\n{instruction}")

    @staticmethod
    def _drop(pkt):
        """
        Mark packet to drop in NFQueue.
        This function was created to support testing surrounding Packet.drop() because cdef functions are un-mockable

        :param pkt: NetfilterQueue Packet.
        :return: None
        """
        pkt.drop()

    @staticmethod
    def _finalize(pkt):
        """
        Send packet back to the NFQueue.
        This function was created to support testing surrounding Packet.accept() because cdef functions are un-mockable

        :param pkt: post-processed NetfilterQueue Packet.
        :return: None
        """
        pkt.accept()
