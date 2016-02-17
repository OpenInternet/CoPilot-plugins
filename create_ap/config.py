from copilot.models.config import Config
from exceptions import ValueError
import subprocess
import re
import os
from os import path

#start logging
import logging
log = logging.getLogger(__name__)

import string

class ConfigWriter(Config):

    def __init__(self):
        super(ConfigWriter, self).__init__()
        self.config_type = "create_ap"
        self.header = ""

    @property
    def ap_password(self):
        return self._ap_password

    @ap_password.setter
    def ap_password(self, plaintext):
        if (8 < len(str(plaintext)) <= 63 and
            all(char in string.printable for char in plaintext)):
            self._ap_password = plaintext
        else:
            raise ValueError("Access Point passwords must be between 8 and 63 characters long and use only printable ASCII characters.")

    @property
    def ap_name(self):
        return self._ap_name

    @ap_name.setter
    def ap_name(self, name):
        if 0 < len(str(name)) <= 31:
            self._ap_name = name
        else:
            raise ValueError("Access Point names must be between 1 and 31 characters long.")

    def add_rule(self, ap_name="copilot", ap_password="copilot_pass", iface_in="eth0", iface_out=None):
        if not iface_out:
            iface_out = get_wireless_interface()
        log.debug("adding create ap rule  {0} {1} {2} {3}".format(iface_out, iface_in, ap_name, ap_password))
        self._rules.append("{0} ".format(iface_out))
        self._rules.append("{0} ".format(iface_in))
        self._rules.append("{0} ".format(ap_name))
        self._rules.append("{0} ".format(ap_password))

    def get_wireless_interface():
        iface_out = None
        name_regex = get_interface_regex("wlan")
        try:
            iface_out = self.get_proc_wifi_interface(name_regex)
        except RuntimeError:
            iface_out = self.get_sys_wifi_interface(name_regex)
        if iface_out = None:
            raise RuntimeError("Unable to identify wireless interface.")
        else:
            return iface_out

    def get_interface_regex(interface_type):
        """ Get a interface regex


        Per: https://github.com/systemd/systemd/blob/5031c4e21b4379c1824033be675517978090fd36/src/udev/udev-builtin-net_id.c#L20

        Regex currently only supports the following types of names:
            [BCMA, CCW, on_board, hotplug, MAC]
        NOTE: Naming by PCI geographical location and USB port number chain not supported.

        Args:
            interface_type (string):
                acceptable values = [eth, serial, wlan, wwan]

        """

        interface_prefixes = {"eth":"en", "serial":"sl",
                              "wlan":"wl", "wwan":"ww"}
        interface_types = [
            "b", # BCMA
            "c", # CCW
            "o", # on_board
            "s", # hotplug
            "x"] # MAC
        name_components = {}
        try:
            name_components['prefix'] = interface_prefixes['interface_type']
        except KeyError:
            raise ValueError("{0} is an invalid interface prefix.".format(interface_type) +
                             "Please use one of the following: {0}".format(interface_prefixes))
        name_components['types'] = "".join(interface_types)
        interface_name_regex = re.compile("{prefix}[{types}]\S*".format(**name_components))
        return interface_name_regex

    def get_proc_wifi_interface(self, wifi_device_regex):
        log.debug("Searching for wireless interface in /proc/net/wireless.")
        ifnames = []
        with open('/proc/net/wireless', 'r') as wireless_process_info:
            file_dump = wireless_process_info.readlines()
            for line in file_dump:
                try:
                    ifnames.append(wifi_device_regex.search(line).group())
                except AttributeError:
                    pass
        if ifnames == []:
            interface_not_found_message = "No wireless interfaces found in /proc/net/wireless. You most likely do not have wireless device attached or the device may not be connected to anything, and as such not producing statistics."
            log.warn(interface_not_found_message)
            raise RuntimeError(interface_not_found_message)
        # We only return the first wireless interface.
        # We may have to change this once we start allowing wireless to wireless bridging
        return ifnames[0]

    def get_sys_wifi_interface(self, wifi_device_regex):
        log.debug("Searching for wireless interface in /sys/class/net.")
        wifi_ifaces = []
        net_iface_root = "/sys/class/net"
        iface_directories = os.listdir(net_iface_root)
        for iface_dir in iface_directories:
            if path.exists(path.join(net_iface_root, iface_dir, "wireless")):
                try:
                    wifi_ifaces.append(wifi_device_regex.search(iface_dir).group())
                except AttributeError:
                    pass
        if wifi_ifaces == []:
            interface_not_found_message = "No wireless interfaces found in /sys/class/net. You most likely do not have wireless device attached."
            log.warn(interface_not_found_message)
            raise RuntimeError(interface_not_found_message)
        # We only return the first wireless interface.
        # We may have to change this once we start allowing wireless to wireless bridging
        return wifi_ifaces[0]


def setup(app):
    new_writer = ConfigWriter()
    app.get_config_writer(new_writer)
