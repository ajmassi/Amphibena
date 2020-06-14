import argparse
import subprocess
import sys


class MitM:
    def __init__(self, interface1, interface2=None):
        """
        Initialize MitM, verifies supplied interfaces exist.

        :param interface1: Primary network interface for MitM. Typically faces a network or server.
        :param interface2: Secondary network interface for network bridge/tap. Typically faces target client.
        :return: None
        """
        self.interface1 = interface1
        self.interface2 = interface2
        self.bridge_name = "ampbr"
        self.kernbr_enabled = None
        self.kernbr_ipv4 = None
        self.kernbr_ipv6 = None
        self.kernbr_arp = None

        self.kern_br_module_up()

        # Interface input validation
        if subprocess.run(['ip', 'address', 'show', 'dev', self.interface1],
                          capture_output=True).returncode != 0:
            print(f"ArgumentError: could not find interface {self.interface1}")
            sys.exit(1)
        elif self.interface2 and \
                subprocess.run(['ip', 'address', 'show', 'dev', self.interface2],
                               capture_output=True).returncode != 0:
            print(f"ArgumentError: could not find interface {self.interface2}")
            sys.exit(1)
        elif self.interface1 and self.interface2 and self.interface1 == self.interface2:
            print(f"ArgumentError: network bridge interfaces cannot be the same")
            sys.exit(1)

    def __del__(self):
        # TODO refactor when arp poisoning integrated
        # Make sure bridge is clean on exit
        if subprocess.run(['ip', 'address', 'show', self.bridge_name],
                          capture_output=True).returncode == 0:
            try:
                subprocess.run(['ip', 'link', 'set', self.bridge_name, 'down'],
                               capture_output=True, check=True)
                subprocess.run(['ip', 'link', 'delete', self.bridge_name, 'type', 'bridge'],
                               capture_output=True, check=True)
                subprocess.run(['iptables', '-D', 'FORWARD', '-i', self.bridge_name, '-j', 'NFQUEUE', '--queue-num', '1'],
                               capture_output=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error tearing down old network bridge: {e}")

        self.kern_br_module_down()

    def kern_br_module_up(self):
        """
        Configures kernel network bridge module to the correct state for packet capture.
        If module is currently in use, values are saved to be restored on program exit.

        :return: None
        """
        try:
            # TODO add logging for kernel module state changes
            if subprocess.run(['test', '-d', '/proc/sys/net/bridge'], capture_output=True).returncode:
                self.kernbr_enabled = False
                subprocess.run(['modprobe', 'br_netfilter'], capture_output=True, check=True)
            else:
                self.kernbr_enabled = True
                self.kernbr_ipv4 = subprocess.run(['cat', '/proc/sys/net/bridge/bridge-nf-call-iptables'],
                                                      capture_output=True).stdout
                self.kernbr_ipv6 = subprocess.run(['cat', '/proc/sys/net/bridge/bridge-nf-call-ip6tables'],
                                                      capture_output=True).stdout
                self.kernbr_arp = subprocess.run(['cat', '/proc/sys/net/bridge/bridge-nf-call-arptables'],
                                                     capture_output=True).stdout

            # TODO 6/14 - subprocess does not like piping in this fashion, requires fix
            subprocess.run(['echo', '1', '>', '/proc/sys/net/bridge/bridge-nf-call-iptables'],
                           capture_output=True, check=True)
            subprocess.run(['echo', '1', '>', '/proc/sys/net/bridge/bridge-nf-call-ip6tables'],
                           capture_output=True, check=True)
            subprocess.run(['echo', '1', '>', '/proc/sys/net/bridge/bridge-nf-call-arptables'],
                           capture_output=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error configuring kernel network bridge module: {e}")

    def kern_br_module_down(self):
        """
        Restore system's kernel network bridge module to initial state.
        Resets original configuration or disables module as appropriate.

        :return: None
        """
        try:
            if self.kernbr_enabled:
                # TODO 6/14 - subprocess does not like piping in this fashion, requires fix
                subprocess.run(['echo', self.kernbr_ipv4, '>', '/proc/sys/net/bridge/bridge-nf-call-iptables'],
                               capture_output=True, check=True)
                subprocess.run(['echo', self.kernbr_ipv6, '>', '/proc/sys/net/bridge/bridge-nf-call-ip6tables'],
                               capture_output=True, check=True)
                subprocess.run(['echo', self.kernbr_arp, '>', '/proc/sys/net/bridge/bridge-nf-call-arptables'],
                               capture_output=True, check=True)
            else:
                subprocess.run(['modprobe', '-r', 'br_netfilter'], capture_output=True, check=True)

        except subprocess.CalledProcessError as e:
            print(f"Error configuring kernel network bridge module: {e}")

    def network_tap(self):
        """
        Establishes network tap over MitM interface1 and interface2.

        :return: None
        """
        # Clean existing bridge from system (could occur on previous shutdown error)
        if subprocess.run(['ip', 'address', 'show', self.bridge_name], capture_output=True).returncode == 0:
            try:
                subprocess.run(['ip', 'link', 'set', self.bridge_name, 'down'],
                               capture_output=True, check=True)
                subprocess.run(['ip', 'link', 'delete', self.bridge_name, 'type', 'bridge'],
                               capture_output=True, check=True)
                subprocess.run(['iptables', '-D', 'FORWARD', '-i', self.bridge_name, '-j', 'NFQUEUE', '--queue-num', '1'],
                               capture_output=True, check=True)
            except subprocess.CalledProcessError as e:
                print(f"Error tearing down old network bridge: {e}")

        # Create bridge on system
        print(f"Constructing network tap between {self.interface1} and {self.interface2}")
        try:
            subprocess.run(['ip', 'link', 'add', self.bridge_name, 'type', 'bridge'],
                           capture_output=True, check=True)
            subprocess.run(['ip', 'link', 'set', self.interface1, 'master', self.bridge_name],
                           capture_output=True, check=True)
            subprocess.run(['ip', 'link', 'set', self.interface2, 'master', self.bridge_name],
                           capture_output=True, check=True)
            subprocess.run(['ip', 'link', 'set', self.bridge_name, 'up'],
                           capture_output=True, check=True)
            subprocess.run(['iptables', '-A', 'FORWARD', '-i', self.bridge_name, '-j', 'NFQUEUE', '--queue-num', '1'],
                           capture_output=True, check=True)
            print(f"Network tap successfully constructed")
        except subprocess.CalledProcessError as e:
            print(f"Error constructing network bridge: {e}")

    def arp_poison(self):
        """
        TODO support network arp poisoning + update class __del__()
        :return: None
        """
        print("Error: Unimplemented function 'arp_poison()'")
        sys.exit(1)


def get_args():
    """
    Parses command line arguments and stores interface names.
    Not expected for mitm.py to be called from the command line often, however this is here just in case.

    :return: parsed_args
    """
    parser = argparse.ArgumentParser(
        description="",
        epilog="ex: mitm.py -i eth0 -b eth1"
    )

    parser.add_argument('-i', required=True,
                        help='Primary network interface for MitM. Typically faces a network or server.')
    parser.add_argument('-b', required=False,
                        help='Secondary network interface for network bridge/tap. Typically faces target client.')

    parsed_args = {key: value for key, value in vars(parser.parse_args()).items()}
    print(parsed_args)

    return parsed_args


def command_line_infect():
    """
    For the uncommon command-line use case.
    Parses command line arguments to generate and start a MitM.

    :return: None
    """
    args = get_args()

    interface1 = args['i']
    interface2 = args['b']

    mitm = MitM(interface1, interface2)

    if mitm.interface2:
        mitm.network_tap()
    else:
        mitm.arp_poison()

    input("Press 'Enter' to close network infection...")


if __name__ == "__main__":
    try:
        command_line_infect()
    except KeyboardInterrupt:
        sys.exit(1)
