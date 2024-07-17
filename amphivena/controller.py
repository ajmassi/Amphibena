import asyncio
import logging
import threading
from asyncio.exceptions import CancelledError

from amphivena import mitm, packet_processor
from amphivena.mitm import MitmError, MitmInterfaceError
from amphivena.playbook import PlaybookValidationError

log = logging.getLogger(__name__)


class Controller:
    """
    Coordinates MitM and PacketProcessor startup/shutdown.
    """

    def __init__(self, iface1: str, iface2: str, playbook: str) -> None:
        """
        :param iface1: Primary network interface for MitM. Typically faces a network or server.
        :param iface2: Optional; Secondary network interface for network bridge/tap. Typically faces target client
        :param playbook: string representation of playbook file path.
        """
        self.__mitm_br = None
        self.__packet_proc = None
        self.__task = None

        self._async_loop = asyncio.get_event_loop()
        self._is_running = False

        self.iface1 = iface1
        self.iface2 = iface2
        self.playbook_file_path = playbook

    @property
    def is_running(self) -> bool:
        return self._is_running

    def halt(self) -> None:
        """Stop MitM and Packet Processor."""
        if self.is_running:
            self.__task.cancel()

    def toggle_running(self) -> None:
        """Will transition the system between running and stopped states."""
        threading.Thread(target=self.__asyncio_thread).start()

    def __asyncio_thread(self) -> None:
        """To be used in thread by toggle_running() to switch system state."""
        if self.is_running:
            self.__task.cancel()
        else:
            self.__task = self._async_loop.create_task(self.start())
            self._async_loop.run_until_complete(self.__task)

    async def start(self) -> None:
        """Start MitM and Packet Processor operations."""
        if self.is_running:
            log.error("start() called while Controller already running")
        else:
            try:
                self._is_running = True
                self.__mitm_br = mitm.MitM(self.iface1, self.iface2)
                self.__packet_proc = packet_processor.PacketProcessor(
                    self.playbook_file_path,
                )

                log.info("Starting mitm and packet processor")
                await asyncio.gather(self.__mitm_br.start(), self.__packet_proc.start())
            except (KeyboardInterrupt, CancelledError):
                pass
            except (
                PermissionError,
                PlaybookValidationError,
                MitmError,
                MitmInterfaceError,
            ):
                log.exception()
            finally:
                await self.stop()

    async def stop(self) -> None:
        """Stop MitM and Packet Processor operations and clean up objects."""
        if self.is_running:
            if self.__mitm_br:
                await self.__mitm_br.stop()
                del self.__mitm_br
                self.__mitm_br = None
            if self.__packet_proc:
                await self.__packet_proc.stop()
                del self.__packet_proc
                self.__packet_proc = None
            self._is_running = False
        else:
            log.error("stop() called while Controller not running")
