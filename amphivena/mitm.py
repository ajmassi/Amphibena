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

# TODO need to centralize/consolidate config options
bridge_nf_state_filepath = "/var/lib/amphivena/br_module_state.json"
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
            os.makedirs(os.path.dirname(bridge_nf_state_filepath), exist_ok=True)
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

        if self._interface2 is None:
            raise AttributeError(
                "Only network tap supported at this time, two interfaces required"
            )

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

        atexit.register(self.teardown)

        self.kernel_br_module_up()

        if self._interface2:
            self.network_tap()
        else:
            self.arp_poison()

        log.info(f"MitM created {self}")
        log.debug(f"{self} params {{{vars(self)}}}")

    def teardown(self):
        """
        Clean up bridge on exit and unregisters self

        :raise RuntimeError: bad interface configuration
        """
        atexit.unregister(self.teardown)

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

                log.info(f"network bridge '{self.bridge_name}' removed")

            except subprocess.CalledProcessError as e:
                raise RuntimeError(
                    f"Network bridge '{self.bridge_name}' teardown encountered error: \n{e}"
                )

        self.kernel_br_module_down()
        log.info(f"MitM {self} teardown complete")

    def kernel_br_module_up(self):
        """
        Configures kernel network bridge module to the correct state for packet capture.
        If module is currently in use, values are saved to be restored on program exit.

        :return: None
        :raise RuntimeError: failure constructing network bridge module
        """
        try:
            # State file should have been deleted on clean exit
            # If it is still present, then notify the user and initialize module normally
            if os.path.exists(bridge_nf_state_filepath):
                log.warning(
                    "Amphivena did not close correctly last session.\n"
                    "Initial system br_netfilter state will be restored at the end of this session"
                )
                log.warning(
                    "Make sure to close the program cleanly using the UI or '^C'"
                )
            else:
                # The br_netfilter kernel module's state is saved to a json file in case of unclean exit
                kernel_br = {}

                if (
                    subprocess.run(
                        "test -d /proc/sys/net/bridge/", capture_output=True, shell=True
                    ).returncode
                    == 0
                ):
                    # Store previous module state if it is active
                    log.debug(
                        "Kernel module 'br_netfilter' already up, saving current settings"
                    )
                    kernel_br["bridge-nf-call-iptables"] = int(
                        subprocess.run(
                            "cat /proc/sys/net/bridge/bridge-nf-call-iptables",
                            capture_output=True,
                            shell=True,
                            check=True,
                        ).stdout
                    )
                    kernel_br["bridge-nf-call-ip6tables"] = int(
                        subprocess.run(
                            "cat /proc/sys/net/bridge/bridge-nf-call-ip6tables",
                            capture_output=True,
                            shell=True,
                            check=True,
                        ).stdout
                    )
                    kernel_br["bridge-nf-call-arptables"] = int(
                        subprocess.run(
                            "cat /proc/sys/net/bridge/bridge-nf-call-arptables",
                            capture_output=True,
                            shell=True,
                            check=True,
                        ).stdout
                    )
                else:
                    kernel_br["br_netfilter_inactive"] = True

                with open(bridge_nf_state_filepath, "w") as f:
                    json.dump(kernel_br, f, indent=4)

            log.debug("Configuring kernel module 'br_netfilter'")
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

            log.info("Kernel module 'br_netfilter' initialized")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error configuring kernel network bridge module: \n{e}")

    def kernel_br_module_down(self):
        """
        Restore system's kernel network bridge module to initial state.
        Resets original configuration or disables module as appropriate.

        :return: None
        :raise RuntimeError: failure resetting network bridge module
        """
        # Retrieve the system's initial bridge module state
        kernel_br = {}
        try:
            with open(bridge_nf_state_filepath, "r") as f:
                kernel_br = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            # If the file does not exist for some reason or has a formatting error we will ignore it
            pass

        try:
            # If the file had parse-able content
            if kernel_br:
                if "bridge-nf-call-iptables" in kernel_br:
                    subprocess.run(
                        "echo "
                        + str(kernel_br.get("bridge-nf-call-iptables"))
                        + " > /proc/sys/net/bridge/bridge-nf-call-iptables",
                        capture_output=True,
                        shell=True,
                        check=True,
                    )

                if "bridge-nf-call-ip6tables" in kernel_br:
                    subprocess.run(
                        "echo "
                        + str(kernel_br.get("bridge-nf-call-ip6tables"))
                        + " > /proc/sys/net/bridge/bridge-nf-call-ip6tables",
                        capture_output=True,
                        shell=True,
                        check=True,
                    )

                if "bridge-nf-call-arptables" in kernel_br:
                    subprocess.run(
                        "echo "
                        + str(kernel_br.get("bridge-nf-call-arptables"))
                        + " > /proc/sys/net/bridge/bridge-nf-call-arptables",
                        capture_output=True,
                        shell=True,
                        check=True,
                    )

                if (
                    "br_netfilter_inactive" in kernel_br
                    and kernel_br["br_netfilter_inactive"]
                ):
                    subprocess.run(
                        "modprobe -r br_netfilter",
                        capture_output=True,
                        shell=True,
                        check=True,
                    )

                os.remove(bridge_nf_state_filepath)

                log.info("Kernel module 'br_netfilter' has been reset to initial state")

        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Kernel network bridge module failed to reset to initial state: \n{e}"
            )
        except AttributeError as e:
            raise e

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
            f"Constructing network tap between {self._interface1} and {self._interface2}"
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
            log.info("Network tap constructed")
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
