import copy
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
    """
    The PacketProcessor operates by retrieving network packets from an existing NFQueue and applying changes based on
        provided playbook configuration. Execution of a PacketProcessor is contained within a separate python process.

    Playbooks are defined by and validated against the schema in "playbook_utils." Default behavior is for each
        playbook instruction to be executed against exactly one packet until all instructions have been expended,
        see "__init__.Config Options" for additional details.
    """

    def __init__(self, playbook_file_path):
        """
        Load configuration from playbook

        Config Options:
            All options are configured at the root level of the playbook.
            * _playbook_is_ordered - required
                True, instructions will be applied in their numbered key order as matching packets are processed
                False, processor will try to match all available instructions against every packet
            * _loop_when_complete [False]
                True, _remaining_instructions will be refreshed from the playbook file once they have all been exhausted
                    This only makes sense when _remove_spent_instructions is True, behaviour will not change when
                    _remove_spent_instructions is False
                False, once all instructions have been exhausted processing is effectively complete and all received
                    packets will just be passed through
            * _remove_spent_instructions [True]
                True, when an instruction is matched and applied to a packet, it will be removed from the
                    _remaining_instructions list
                False, instructions will remain active and will be applied to any matching packets that arrive during
                    processing

        :param playbook_file_path: string representation of playbook file path.
        :return: PacketProcessor
        :raise PlaybookValidationError: Raised during playbook validation.
        """
        try:
            self._playbook_data = playbook_utils.load(playbook_file_path)
        except playbook_utils.PlaybookValidationError as e:
            raise e

        self._remaining_instructions = copy.deepcopy(
            self._playbook_data.get("instructions")
        )
        self._playbook_is_ordered = self._playbook_data.get("isOrdered")
        self._loop_when_complete = self._playbook_data.get("loopWhenComplete", False)
        self._remove_spent_instructions = self._playbook_data.get(
            "removeSpentInstructions", True
        )
        self.proc = None

    async def start(self):
        """
        Spin off PacketProcessor process and begin execution.

        :return: multiprocessing.Process
        """
        self.proc = multiprocessing.Process(target=self._examine_packets)
        self.proc.start()
        return self.proc

    async def stop(self):
        """
        Stop PacketProcessor process execution.
        """
        # TODO review this statement:
        #   if self.proc._closed is False:
        self.proc.terminate()
        self.proc.join()
        self.proc.close()

    def _examine_packets(self):
        """
        Pull packets from NFQueue for processing.
        """
        nfqueue = netfilterqueue.NetfilterQueue()
        nfqueue.bind(1, self._process)
        try:
            log.info("Starting nfqueue")
            nfqueue.run()
        except KeyboardInterrupt:
            log.warning("Caught keyboard interrupt")
        finally:
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

        # Delete fields that will be recalculated by scapy
        if instr_list:
            for layer in scapy_packet.layers():
                try:
                    del scapy_packet.getlayer(layer).fields["chksum"]
                except KeyError:
                    pass

                try:
                    del scapy_packet.getlayer(layer).fields["len"]
                except KeyError:
                    pass

        pkt.set_payload(scapy_packet.build())
        self._finalize(pkt)

    def _assemble_instruction_list(self, scapy_packet):
        """
        Evaluate how many, if any, playbook instruction(s) will be executed against scapy_packet.
        For ordered operations, can execute multiple sequential operations if they all match current packet

        :param scapy_packet: Scapy.Packet - parsed from NFQueue
        :return: list of instructions from playbook to be executed against scapy_packet
        """
        if not self._remaining_instructions:
            log.error("No packet operations left!")
            return None

        instr_list = []

        if self._playbook_is_ordered:
            for i in sorted(self._remaining_instructions):
                instr = self._remaining_instructions.get(i)
                matching = self._analyze_packet(scapy_packet, instr)
                # Multiple instructions can be executed against the same packet, break when a match is not found
                if not matching:
                    break
                if self._remove_spent_instructions:
                    self._remaining_instructions.pop(i)
                instr_list.append(instr)

        else:
            # Pool execution does not care about the order, skip sorting
            for i in self._remaining_instructions:
                instr = self._remaining_instructions.get(i)
                matching = self._analyze_packet(scapy_packet, instr)
                if matching:
                    if self._remove_spent_instructions:
                        self._remaining_instructions.pop(i)
                    instr_list.append(instr)

        if not self._remaining_instructions and self._loop_when_complete:
            self._remaining_instructions = copy.deepcopy(
                self._playbook_data.get("instructions")
            )

        return instr_list

    @staticmethod
    def _analyze_packet(scapy_packet, instruction):
        """
        Evaluate scapy_packet against the current instruction's conditions to determine if the given step will execute.

        :param scapy_packet: Scapy.Packet - parsed from NFQueue
        :param instruction: dict - playbook instruction
        :return: boolean
        """
        if conditions := instruction.get("conditions"):
            for c in conditions:
                layer = c.get("layer")
                if scapy_packet.haslayer(layer):
                    try:
                        packet_field = getattr(scapy_packet.getlayer(layer), c["field"])
                        # TODOish An assumption is made here that we want to attempt type-sameness, but we might want a
                        #  mode that throws caution to the wind
                        try:
                            comp_value = type(packet_field)(c["value"])
                        except ValueError as e:
                            log.error(e)
                            return False

                        if packet_field != comp_value:
                            log.debug(f"`{packet_field}` != `{comp_value}`")
                            return False
                    except AttributeError:
                        log.error(
                            f"Condition `{c}` attempted\nTarget packet does not contain field `{c['field']}`"
                        )
                        return False
                else:
                    log.error(
                        f"Instruction `{instruction}` attempted\nTarget packet does not contain layer `{layer}`"
                    )
                    return False
        else:
            log.debug(f"No conditions for instruction `{instruction}`")

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
                if scapy_packet.haslayer(layer):
                    if a.get("type") == "modify":
                        try:
                            packet_field = getattr(
                                scapy_packet.getlayer(layer), a["field"]
                            )

                            try:
                                new_value = type(packet_field)(a["value"])
                            except ValueError as e:
                                log.error(e)
                                return False

                            setattr(
                                scapy_packet.getlayer(instruction.get("layer")),
                                a.get("field"),
                                new_value,
                            )

                        except AttributeError:
                            log.error(
                                f"Action `{a}` attempted\nTarget packet does not contain field `{a['field']}`"
                            )
                            return False
                else:
                    log.error(
                        f"Instruction `{instruction}` attempted\nTarget packet does not contain layer `{layer}`"
                    )
        else:
            log.warning(f"No actions set for instruction:\n{instruction}")

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
