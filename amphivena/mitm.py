import argparse
import asyncio
import atexit
import json
import logging
import logging.config
import os
import pathlib
import shlex
import subprocess  # nosec B404
import sys

from dotenv import load_dotenv

load_dotenv()
bridge_nf_state_filepath = os.getenv("BRIDGE_NF_STATE_FILEPATH")
log = logging.getLogger(__name__)


class MitmError(Exception):
    """Base class for exceptions raised during MitM lifecycle."""
    def __init__(self, message):
        self.message = message
        super().__init__(message)


class MitmInterfaceError(MitmError):
    """Raised when there is a problem with a MitM interface."""
    def __init__(self, message):
        self.message = message
        super().__init__(message)


class MitmKernelBrError(MitmError):
    """Raised when there is a problem with the kernel bridge module."""
    def __init__(self, message):
        self.message = message
        super().__init__(message)


def kernel_br_save_state():
    kernel_br_state = {}

    try:
        if (
            subprocess.run(  # nosec B603
                shlex.split("/bin/test -d /proc/sys/net/bridge/"),
                capture_output=True,
                shell=False,
            ).returncode
            == 0
        ):
            log.debug(
                "Kernel module 'br_netfilter' already up, saving current settings"
            )
            with open("/proc/sys/net/bridge/bridge-nf-call-iptables", "r") as f:
                kernel_br_state["bridge-nf-call-iptables"] = int(f.read())

            with open(
                    "/proc/sys/net/bridge/bridge-nf-call-ip6tables", "r"
            ) as f:
                kernel_br_state["bridge-nf-call-ip6tables"] = int(f.read())

            with open(
                    "/proc/sys/net/bridge/bridge-nf-call-arptables", "r"
            ) as f:
                kernel_br_state["bridge-nf-call-arptables"] = int(f.read())

        else:
            kernel_br_state["br_netfilter_inactive"] = True

    except subprocess.CalledProcessError as e:
        raise MitmKernelBrError(
            f"Error saving current br_netfilter state: {e}"
        ) from e

    with open(bridge_nf_state_filepath, "w") as f:
        json.dump(kernel_br_state, f, indent=4)


def kernel_br_module_up():
    """
    Configures kernel network bridge module for packet capture.
    If module is currently in use, values are saved to be restored on program exit.

    :return: None
    :raise MitmKernelBrError: failure constructing network bridge module
    """
    try:
        if os.path.exists(bridge_nf_state_filepath):
            log.warning(
                "Amphivena did not close correctly last session.\n"
                "Initial system br_netfilter state will be restored at the end of this session"
            )
            log.warning(
                "Make sure to close the program cleanly using the UI or '^C'"
            )
        else:
            kernel_br_save_state()

        log.debug("Configuring kernel module 'br_netfilter'")
        subprocess.run(  # nosec B603
            shlex.split("/usr/sbin/modprobe br_netfilter"),
            capture_output=True,
            shell=False,
            check=True,
        )

        with open("/proc/sys/net/bridge/bridge-nf-call-iptables", "w") as f:
            f.write("1")

        with open("/proc/sys/net/bridge/bridge-nf-call-ip6tables", "w") as f:
            f.write("1")

        with open("/proc/sys/net/bridge/bridge-nf-call-arptables", "w") as f:
            f.write("1")

        log.info("Kernel module 'br_netfilter' initialized")

    except subprocess.CalledProcessError as e:
        raise MitmKernelBrError(
            f"Error configuring kernel network bridge module: \n{e}"
        ) from e


def kernel_br_module_down():
    """
    Restore system's kernel network bridge module to initial state.
    Resets original configuration or disables module as appropriate.

    :return: None
    :raise MitmKernelBrError: failure resetting network bridge module
    """
    kernel_br_state = {}
    try:
        with open(bridge_nf_state_filepath, "r") as f:
            kernel_br_state = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        log.warning(f"Error parsing kernel module br_netfilter backup: {e}")
        pass

    if kernel_br_state:
        if "bridge-nf-call-iptables" in kernel_br_state:
            with open("/proc/sys/net/bridge/bridge-nf-call-iptables", "w") as f:
                f.write(str(kernel_br_state.get("bridge-nf-call-iptables")))

        if "bridge-nf-call-ip6tables" in kernel_br_state:
            with open(
                "/proc/sys/net/bridge/bridge-nf-call-ip6tables", "w"
            ) as f:
                f.write(str(kernel_br_state.get("bridge-nf-call-ip6tables")))

        if "bridge-nf-call-arptables" in kernel_br_state:
            with open(
                "/proc/sys/net/bridge/bridge-nf-call-arptables", "w"
            ) as f:
                f.write(str(kernel_br_state.get("bridge-nf-call-arptables")))

        if (
            "br_netfilter_inactive" in kernel_br_state
            and kernel_br_state["br_netfilter_inactive"]
        ):
            try:
                subprocess.run(  # nosec B603
                    shlex.split("/usr/sbin/modprobe -r br_netfilter"),
                    capture_output=True,
                    shell=False,
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                raise MitmKernelBrError(
                    f"Kernel network bridge module failed to reset to initial state: \n{e}"
                ) from e

        os.remove(bridge_nf_state_filepath)

        log.info("Kernel module 'br_netfilter' has been reset to initial state")


class MitM:
    def __new__(cls, *args, **kwargs):
        """
        Create MitM instance, verify permissions

        :return: MitM object
        :raise PermissionError: root-level permissions required
        """
        if os.geteuid() != 0:
            raise PermissionError(
                "Root privileges are required for 'MitM' creation, try restarting the application using 'sudo'."
            )
        else:
            os.makedirs(os.path.dirname(bridge_nf_state_filepath), exist_ok=True)
            return super(MitM, cls).__new__(cls)

    def __init__(self, interface1, interface2=None):
        """
        Initialize MitM, verifies supplied interfaces exist.

        :param interface1: Required, Primary network interface for MitM. Typically faces a network or server.
        :param interface2: Optional, Secondary network interface for network bridge/tap. Typically faces target client.
        :return: None
        :raise MitmInterfaceError: bad interface configuration
        """
        self._interface1 = interface1
        self._interface2 = interface2
        self.bridge_name = "ampbr"

        if self._interface2 is None:
            raise MitmInterfaceError(
                "Only network tap supported at this time, two interfaces required"
            )

        try:
            subprocess.run(  # nosec B603
                shlex.split(
                    "/bin/ip address show dev " + shlex.quote(self._interface1)
                ),
                capture_output=True,
                shell=False,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise MitmInterfaceError(
                f"Provided interface (iface1: '{self._interface1}') not found on local machine"
            ) from e

        if self._interface2:
            try:
                subprocess.run(  # nosec B603
                    shlex.split(
                        "/bin/ip address show dev " + shlex.quote(self._interface2)
                    ),
                    capture_output=True,
                    shell=False,
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                raise MitmInterfaceError(
                    f"Provided interface (iface2: '{self._interface2}') not found on local machine"
                ) from e

        if (
            self._interface1
            and self._interface2
            and self._interface1 == self._interface2
        ):
            raise MitmInterfaceError("Provided network bridge interfaces cannot be the same")

        atexit.register(self.stop)

        log.info(f"MitM created {self}")
        log.debug(f"{self} params {{{vars(self)}}}")

    async def start(self):
        """Configure and start MitM operation."""
        kernel_br_module_up()

        if self._interface2:
            self.activate_network_tap()
        else:
            self.arp_poison()

        log.info(f"MitM started {self}")

        while True:
            await asyncio.sleep(0.1)

    async def stop(self):
        """Stop current operation and reset any changes made to the host."""
        atexit.unregister(self.stop)
        self.deactivate_network_tap()
        kernel_br_module_down()
        log.info(f"MitM stopped {self}")

    def activate_network_tap(self):
        """
        Establishes network tap over MitM interface1 and interface2.

        :return: None
        :raise MitmInterfaceError: failure constructing bridge
        """
        # Clean existing bridge from system (could be left behind after previous shutdown error)
        if (
            subprocess.run(  # nosec B603
                shlex.split("/bin/ip address show " + shlex.quote(self.bridge_name)),
                capture_output=True,
                shell=False,
            ).returncode
            == 0
        ):
            try:
                subprocess.run(  # nosec B603
                    shlex.split(
                        "/bin/ip link set " + shlex.quote(self.bridge_name) + " down"
                    ),
                    capture_output=True,
                    shell=False,
                    check=True,
                )
                subprocess.run(  # nosec B603
                    shlex.split(
                        "/bin/ip link delete "
                        + shlex.quote(self.bridge_name)
                        + " type bridge"
                    ),
                    capture_output=True,
                    shell=False,
                    check=True,
                )
                subprocess.run(  # nosec B603
                    shlex.split(
                        "/usr/sbin/iptables -D FORWARD -i "
                        + shlex.quote(self.bridge_name)
                        + " -j NFQUEUE --queue-num 1"
                    ),
                    capture_output=True,
                    shell=False,
                    check=True,
                )

            except subprocess.CalledProcessError as e:
                raise MitmInterfaceError(
                    f"Failure tearing down old network bridge: \n{e}"
                ) from e

        # Create bridge on system
        log.info(
            f"Constructing network tap between {self._interface1} and {self._interface2}"
        )
        try:
            subprocess.run(  # nosec B603
                shlex.split(
                    "/bin/ip link add " + shlex.quote(self.bridge_name) + " type bridge"
                ),
                capture_output=True,
                shell=False,
                check=True,
            )
            subprocess.run(  # nosec B603
                shlex.split(
                    "/bin/ip link set "
                    + shlex.quote(self._interface1)
                    + " master "
                    + shlex.quote(self.bridge_name)
                ),
                capture_output=True,
                shell=False,
                check=True,
            )
            subprocess.run(  # nosec B603
                shlex.split(
                    "/bin/ip link set "
                    + shlex.quote(self._interface2)
                    + " master "
                    + shlex.quote(self.bridge_name)
                ),
                capture_output=True,
                shell=False,
                check=True,
            )
            subprocess.run(  # nosec B603
                shlex.split(
                    "/bin/ip link set " + shlex.quote(self.bridge_name) + " up"
                ),
                capture_output=True,
                shell=False,
                check=True,
            )
            subprocess.run(  # nosec B603
                shlex.split(
                    "/usr/sbin/iptables -A FORWARD -i ampbr -j NFQUEUE --queue-num 1"
                ),
                capture_output=True,
                shell=False,
                check=True,
            )
            log.info("Network tap constructed")
        except subprocess.CalledProcessError as e:
            raise MitmInterfaceError(f"Failure constructing network bridge: {e}") from e

    def deactivate_network_tap(self):
        """
        Remove network tap over MitM interface1 and interface2.

        :return: None
        :raise MitmInterfaceError: failure during bridge teardown
        """
        if (
            subprocess.run(  # nosec B603
                shlex.split("/bin/ip address show " + shlex.quote(self.bridge_name)),
                capture_output=True,
                shell=False,
            ).returncode
            == 0
        ):
            try:
                subprocess.run(  # nosec B603
                    shlex.split(
                        "/bin/ip link set " + shlex.quote(self.bridge_name) + " down"
                    ),
                    capture_output=True,
                    shell=False,
                    check=True,
                )
                subprocess.run(  # nosec B603
                    shlex.split(
                        "/bin/ip link delete "
                        + shlex.quote(self.bridge_name)
                        + " type bridge"
                    ),
                    capture_output=True,
                    shell=False,
                    check=True,
                )
                subprocess.run(  # nosec B603
                    shlex.split(
                        "/usr/sbin/iptables -D FORWARD -i ampbr -j NFQUEUE --queue-num 1"
                    ),
                    capture_output=True,
                    shell=False,
                    check=True,
                )

                log.info(f"network bridge '{self.bridge_name}' removed")

            except subprocess.CalledProcessError as e:
                raise MitmInterfaceError(
                    f"Network bridge '{self.bridge_name}' teardown encountered error: \n{e}"
                ) from e

    def arp_poison(self):
        """
        :raise NotImplementedError
        """
        raise NotImplementedError("unimplemented function 'arp_poison()'")


def get_args():
    """
    Parses command line arguments and stores interface names.
    Not expected for mitm.py to be called from the command line often, however this is here just in case.

    :return: parsed_args
    """
    parser = argparse.ArgumentParser(
        description="", epilog="ex: mitm.py -i eth0 -b eth1"
    )

    parser.add_argument(
        "-i",
        required=True,
        help="Primary network interface for MitM. Typically faces a network or server.",
    )
    parser.add_argument(
        "-b",
        required=False,
        help="Secondary network interface for network bridge/tap. Typically faces target client.",
    )

    parsed_args = {key: value for key, value in vars(parser.parse_args()).items()}

    return parsed_args


def command_line_infect():
    """
    For the uncommon command-line use case.
    Parses command line arguments to generate and start a MitM.

    :return: None
    """
    config_directory = pathlib.Path(__file__).parent.absolute()
    with open(config_directory.joinpath("logger.conf")) as logger_conf:
        logging.config.dictConfig(json.load(logger_conf))

    args = get_args()

    interface1 = args["i"]
    interface2 = args["b"]

    try:
        _ = MitM(interface1, interface2)
        input("Press 'Enter' to stop network infection...")
    except (PermissionError, RuntimeError) as e:
        log.error(e)
        return


if __name__ == "__main__":
    try:
        command_line_infect()
    except KeyboardInterrupt:
        sys.exit(1)
