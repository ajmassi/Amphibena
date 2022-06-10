import json
import logging
import multiprocessing

import netfilterqueue
import scapy.layers.tls.handshake
from scapy.compat import raw
from scapy.layers.l2 import Ether
from scapy.layers.tls.record import TLS

log = logging.getLogger(__name__)


class PacketProcessor:
    def __init__(self, config_file_path):
        self._config_data = {}
        try:
            with open(config_file_path, "r") as f:
                self._config_data = json.load(f)
        except FileNotFoundError():
            print("File not found")

        # TODO Create config meta setting for "ordered" vs. "pool" step execution
        self._config_is_ordered = self._config_data.get("isOrdered")
        self._current_step = 1
        self._step_count = len(self._config_data.get("instructions"))
        self.proc = None

    def start(self):
        self.proc = multiprocessing.Process(target=self.examine_packets)
        self.proc.start()
        return self.proc

    def stop(self):
        # TODO: This works but is sketchy, should consider better means of controlling the process
        if self.proc._closed is False:
            self.proc.terminate()
            self.proc.join()
            self.proc.close()

    def examine_packets(self):
        nfqueue = netfilterqueue.NetfilterQueue()
        nfqueue.bind(1, self._process)
        try:
            print("starting nfqueue")
            log.info("starting nfqueue")
            nfqueue.run()
        except KeyboardInterrupt:
            print("shutting down nfqueue")

        nfqueue.unbind()

    def _process(self, pkt):
        # Parse packet
        # TODO using 'Ether' should work for initial use cases and testing, but may need to work out better future solution
        scapy_packet = Ether(raw(pkt.get_payload()))

        instr_list = self._assemble_instruction_list(scapy_packet)

        for instruction in instr_list:
            try:
                if instruction["operation"] == "Drop":
                    pkt.drop()
                    return
                elif instruction["operation"] == "Edit":
                    self._edit_packet(scapy_packet, instruction)
                else:
                    log.error(
                        f"Unknown packet operation {instruction.get('operation')}"
                    )
            except KeyError:
                log.error("Packet operation [Drop, Edit] not defined.")

        pkt.set_payload(scapy_packet.build())
        self._finalize(pkt)

    def _assemble_instruction_list(self, scapy_packet):
        # Determine instruction(s) to be executed against current packet

        # TODO define behavior for pool execution
        instr_list = self._config_data.get("instructions")
        # If instructions are to be executed in order, assign next step
        if self._config_is_ordered:
            if self._current_step > self._step_count:
                log.error("No packet operations left!")
                return None

            instr_list = [
                self._config_data.get("instructions").get(str(self._current_step))
            ]
            self._current_step += 1

        # Remove instructions that do not map to current packet
        for i in instr_list:
            matching = self._analyze_packet(scapy_packet, i)
            if not matching:
                instr_list.remove(i)

        return instr_list

    @staticmethod
    def _analyze_packet(scapy_packet, instruction):
        # process instruction.conditions
        layer = instruction.get("layer")

        # Check scapy_packet for layer and conditionals we are looking for
        if scapy_packet.haslayer(layer):
            # If we have conditionals, we will check them against the scapy_packet
            if conditions := instruction.get("conditions"):
                for c in conditions:
                    # TODO add operands: !=, contains, !contains
                    # TODO Negative check may be confusing and non-pytonic, worth reviewing
                    if not getattr(scapy_packet.getlayer(layer), c["field"]) == int(
                        c["value"]
                    ):
                        return False
            else:
                # If there are no conditions specified then we are done
                return True
        else:
            return False
        # TODO Pretty ugly cascade here, sometime clean up this logic?
        return True

    @staticmethod
    def _edit_packet(scapy_packet, instruction):
        if actions := instruction.get("actions"):
            for action in actions:
                # TODO operation for inserting arbitrary bytes at?/before/after location
                if action.get("type") == "modify":
                    try:
                        val = int(action.get("val"))
                    except ValueError:
                        # TODO garbage in handling (tho this applies everywhere...)
                        val = int(action.get("val"), 16)

                    setattr(
                        scapy_packet.getlayer(instruction.get("layer")),
                        action.get("field"),
                        val,
                    )
        else:
            log.error(f"No actions set for instruction:\n{instruction}")

    @staticmethod
    def _finalize(pkt):
        # Wrapped for mocking during tests - cdef functions are un-mockable
        pkt.accept()
