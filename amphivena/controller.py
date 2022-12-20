import asyncio
import logging

from amphivena import mitm, packet_processor

log = logging.getLogger(__name__)


class Controller(object):
    """
    Coordinates start of mitm and packet processor and waits for shutdown signal.
    """

    __instance = None
    __mitm_br = None
    __packet_proc = None

    def __new__(cls, iface1, iface2, playbook):
        if not hasattr(cls, "instance"):
            cls.__instance = super(Controller, cls).__new__(cls)
        return cls.__instance

    def __init__(self, iface1, iface2, playbook):
        """
        :param iface1: Primary network interface for MitM. Typically faces a network or server.
        :param iface2: Optional; Secondary network interface for network bridge/tap. Typically faces target client
        :param playbook: string representation of playbook file path.
        """
        self.__mitm_br = mitm.MitM(iface1, iface2)
        self.__packet_proc = packet_processor.PacketProcessor(playbook)

    @property
    def mitm_br(self):
        return self.__mitm_br

    @mitm_br.setter
    def mitm_br(self, iface1, iface2):
        self.__mitm_br = mitm.MitM(iface1, iface2)

    @property
    def packet_proc(self):
        return self.__packet_proc

    async def engage(self):
        try:
            log.info("Starting mitm and packet processor.")
            await asyncio.gather(self.__mitm_br.start(), self.packet_proc.start())
        except KeyboardInterrupt:
            pass
        finally:
            await self.disengage()

    async def disengage(self):
        await self.mitm_br.teardown()
        await self.packet_proc.stop()
