import asyncio
import logging
import threading
from asyncio.exceptions import CancelledError

from amphivena import mitm, packet_processor
from amphivena.playbook_utils import PlaybookValidationError

log = logging.getLogger(__name__)


class Controller(object):
    """
    Coordinates start of mitm and packet processor and waits for shutdown signal.
    """

    def __init__(self, iface1, iface2, playbook):
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

        self.config = {
            "iface1": iface1,
            "iface2": iface2,
            "playbook_file_path": playbook,
        }

    @property
    def is_running(self):
        return self._is_running

    def halt(self):
        if self.is_running:
            self.__task.cancel()

    def onoff_toggle(self):
        threading.Thread(target=self._asyncio_thread).start()

    def _asyncio_thread(self):
        if self.is_running:
            self.__task.cancel()
        else:
            self.__task = self._async_loop.create_task(self._engage())
            self._async_loop.run_until_complete(self.__task)

    async def _engage(self):
        if self.is_running:
            log.error("engage() called while Controller already running")
        else:
            try:
                self._is_running = True
                self.__mitm_br = mitm.MitM(
                    self.config.get("iface1"), self.config.get("iface2")
                )
                self.__packet_proc = packet_processor.PacketProcessor(
                    self.config.get("playbook_file_path")
                )

                log.info("Starting mitm and packet processor")
                await asyncio.gather(self.__mitm_br.start(), self.__packet_proc.start())
            except (KeyboardInterrupt, CancelledError):
                pass
            except (
                PermissionError,
                RuntimeError,
                AttributeError,
                PlaybookValidationError,
            ) as e:
                log.error(e)
            finally:
                await self._halt()

    async def _halt(self):
        if self.is_running:
            if self.__mitm_br:
                await self.__mitm_br.teardown()
                del self.__mitm_br
                self.__mitm_br = None
            if self.__packet_proc:
                await self.__packet_proc.stop()
                del self.__packet_proc
                self.__packet_proc = None
            self._is_running = False
        else:
            log.error("halt() called while Controller not running")
