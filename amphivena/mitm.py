import argparse
import atexit
import json
import logging
import logging.config
import os
import pathlib
import shlex
import subprocess
import sys

log = logging.getLogger(__name__)


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
            return super(MitM, cls).__new__(cls)

    def __init__(self, interface1, interface2=None):
        """
        Initialize MitM, verifies supplied interfaces exist.

        :param interface1: Primary network interface for MitM. Typically faces a network or server.
        :param interface2: Secondary network interface for network bridge/tap. Typically faces target client.
        :return: None
        :raise RuntimeError: bad interface configuration
        """
        self._interface1 = interface1
        self._interface2 = interface2
        self.bridge_name = "ampbr"

        # Track if machine had br_netfilter enabled before mitm execution
        self.__kernel_bridge_previously_enabled = True
        self.__kernel_br_ipv4 = None
        self.__kernel_br_ipv6 = None
        self.__kernel_br_arp = None

        # Interface input validation
        # interface1 required in all circumstances; check interface2 if it is provided
        try:
            subprocess.run(
                "ip address show dev " + shlex.quote(self._interface1),
                capture_output=True,
                shell=True,
                check=True,
            )
            if self._interface2:
                subprocess.run(
                    "ip address show dev " + shlex.quote(self._interface2),
                    capture_output=True,
                    shell=True,
                    check=True,
                )
        except subprocess.CalledProcessError:
            raise RuntimeError("Provided interface not found on local machine")

        if (
            self._interface1
            and self._interface2
            and self._interface1 == self._interface2
        ):
            raise RuntimeError("Provided network bridge interfaces cannot be the same")

        # atexit.register(self.teardown)
        self.kernel_br_module_up()

        if self._interface2:
            self.network_tap()
        else:
            self.arp_poison()

        log.info(f"MitM created {self}")
        log.debug(f"{self} params {{{vars(self)}}}")

    def __del__(self):
        self.teardown()

    def teardown(self):
        """
        Clean up bridge on exit

        :raise RuntimeError: bad interface configuration
        """
        if (
            subprocess.run(
                "ip address show " + shlex.quote(self.bridge_name),
                capture_output=True,
                shell=True,
            ).returncode
            == 0
        ):
            try:
                subprocess.run(
                    "ip link set " + shlex.quote(self.bridge_name) + " down",
                    capture_output=True,
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    "ip link delete " + shlex.quote(self.bridge_name) + " type bridge",
                    capture_output=True,
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    "iptables -D FORWARD -i "
                    + shlex.quote(self.bridge_name)
                    + " -j NFQUEUE --queue-num 1",
                    capture_output=True,
                    shell=True,
                    check=True,
                )

                log.info(f"network bridge '{self.bridge_name}' successfully removed")

            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"Network bridge '{self.bridge_name}' teardown encountered error: \n{e}"
                )

        self.kernel_br_module_down()
        log.info(f"MitM {self} teardown complete")

        # atexit.unregister(self.teardown)

    def kernel_br_module_up(self):
        """
        Configures kernel network bridge module to the correct state for packet capture.
        If module is currently in use, values are saved to be restored on program exit.

        :return: None
        :raise RuntimeError: failure constructing network bridge module
        """
        try:
            if (
                subprocess.run(
                    "test -d /proc/sys/net/bridge", capture_output=True, shell=True
                ).returncode
                == 0
            ):
                log.debug(
                    "kernel module 'br_netfilter' already up, saving current settings"
                )
                self.__kernel_bridge_previously_enabled = True
                self.__kernel_br_ipv4 = subprocess.run(
                    "cat /proc/sys/net/bridge/bridge-nf-call-iptables",
                    capture_output=True,
                    shell=True,
                    check=True,
                ).stdout
                self.__kernel_br_ipv6 = subprocess.run(
                    "cat /proc/sys/net/bridge/bridge-nf-call-ip6tables",
                    capture_output=True,
                    shell=True,
                    check=True,
                ).stdout
                self.__kernel_br_arp = subprocess.run(
                    "cat /proc/sys/net/bridge/bridge-nf-call-arptables",
                    capture_output=True,
                    shell=True,
                    check=True,
                ).stdout
            else:
                log.debug("activating kernel module 'br_netfilter'")
                self.__kernel_bridge_previously_enabled = False
                subprocess.run(
                    "modprobe br_netfilter", capture_output=True, shell=True, check=True
                )

            subprocess.run(
                "echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables",
                capture_output=True,
                shell=True,
                check=True,
            )
            subprocess.run(
                "echo 1 > /proc/sys/net/bridge/bridge-nf-call-ip6tables",
                capture_output=True,
                shell=True,
                check=True,
            )
            subprocess.run(
                "echo 1 > /proc/sys/net/bridge/bridge-nf-call-arptables",
                capture_output=True,
                shell=True,
                check=True,
            )

            log.info("kernel module 'br_netfilter' successfully initialized")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error configuring kernel network bridge module: \n{e}")

    def kernel_br_module_down(self):
        """
        Restore system's kernel network bridge module to initial state.
        Resets original configuration or disables module as appropriate.

        :return: None
        :raise RuntimeError: failure resetting network bridge module
        """
        try:
            if self.__kernel_bridge_previously_enabled:
                subprocess.run(
                    "echo "
                    + shlex.quote(self.__kernel_br_ipv4.decode("utf-8").rstrip())
                    + " > /proc/sys/net/bridge/bridge-nf-call-iptables",
                    capture_output=True,
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    "echo "
                    + shlex.quote(self.__kernel_br_ipv6.decode("utf-8").rstrip())
                    + " > /proc/sys/net/bridge/bridge-nf-call-ip6tables",
                    capture_output=True,
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    "echo "
                    + shlex.quote(self.__kernel_br_arp.decode("utf-8").rstrip())
                    + " > /proc/sys/net/bridge/bridge-nf-call-arptables",
                    capture_output=True,
                    shell=True,
                    check=True,
                )
            else:
                subprocess.run(
                    "modprobe -r br_netfilter",
                    capture_output=True,
                    shell=True,
                    check=True,
                )

            log.info("kernel module 'br_netfilter' successfully reset to initial state")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Kernel network bridge module failed to reset to initial state: \n{e}"
            )

    def network_tap(self):
        """
        Establishes network tap over MitM interface1 and interface2.

        :return: None
        :raise RuntimeError: failure constructing bridge
        """
        # Clean existing bridge from system (could be left behind after previous shutdown error)
        if (
            subprocess.run(
                "ip address show " + shlex.quote(self.bridge_name),
                capture_output=True,
                shell=True,
            ).returncode
            == 0
        ):
            try:
                subprocess.run(
                    "ip link set " + shlex.quote(self.bridge_name) + " down",
                    capture_output=True,
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    "ip link delete " + shlex.quote(self.bridge_name) + " type bridge",
                    capture_output=True,
                    shell=True,
                    check=True,
                )
                subprocess.run(
                    "iptables -D FORWARD -i "
                    + shlex.quote(self.bridge_name)
                    + " -j NFQUEUE --queue-num 1",
                    capture_output=True,
                    shell=True,
                    check=True,
                )

            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failure tearing down old network bridge: \n{e}")

        # Create bridge on system
        log.info(
            f"constructing network tap between {self._interface1} and {self._interface2}"
        )
        try:
            subprocess.run(
                "ip link add " + shlex.quote(self.bridge_name) + " type bridge",
                capture_output=True,
                shell=True,
                check=True,
            )
            subprocess.run(
                "ip link set "
                + shlex.quote(self._interface1)
                + " master "
                + shlex.quote(self.bridge_name),
                capture_output=True,
                shell=True,
                check=True,
            )
            subprocess.run(
                "ip link set "
                + shlex.quote(self._interface2)
                + " master "
                + shlex.quote(self.bridge_name),
                capture_output=True,
                shell=True,
                check=True,
            )
            subprocess.run(
                "ip link set " + shlex.quote(self.bridge_name) + " up",
                capture_output=True,
                shell=True,
                check=True,
            )
            subprocess.run(
                "iptables -A FORWARD -i "
                + shlex.quote(self.bridge_name)
                + " -j NFQUEUE --queue-num 1",
                capture_output=True,
                shell=True,
                check=True,
            )
            log.info("Network tap successfully constructed")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failure constructing network bridge: {e}")

    def arp_poison(self):
        """
        TODO support network arp poisoning + update teardown()
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
    # print(parsed_args)

    return parsed_args


def command_line_infect():
    """
    For the uncommon command-line use case.
    Parses command line arguments to generate and start a MitM.

    :return: None
    """
    # Configure logger
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
