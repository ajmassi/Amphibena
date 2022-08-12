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
                    pkt.drop()
                    # self._current_step += 1
                    return
                elif instruction["operation"] == "edit":
                    self._edit_packet(scapy_packet, instruction)
                    # self._current_step += 1
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
        layer = instruction.get("layer")
        # Check scapy_packet for layer and conditionals we are looking for
        if scapy_packet.haslayer(layer):
            # If we have conditionals, we will check them against the scapy_packet
            if conditions := instruction.get("conditions"):
                for c in conditions:
                    try:
                        val = int(c.get("value"))
                    except ValueError:
                        val = int(c.get("value"), 16)

                    if not getattr(scapy_packet.getlayer(layer), c["field"]) == val:
                        return False
            else:
                # If there are no conditions specified, then we are done
                return True
        else:
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
            for action in actions:
                if action.get("type") == "modify":
                    try:
                        val = int(action.get("value"))
                    except ValueError:
                        val = int(action.get("value"), 16)

                    setattr(
                        scapy_packet.getlayer(instruction.get("layer")),
                        action.get("field"),
                        val,
                    )
        else:
            log.error(f"No actions set for instruction:\n{instruction}")

    @staticmethod
    def _finalize(pkt):
        """
        Send packet back to the NFQueue.
        This function was created to support testing surrounding Packet.accept() because cdef functions are un-mockable

        :param pkt: post-processed NetfilterQueue Packet.
        :return: None
        """
        pkt.accept()
