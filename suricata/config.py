from copilot.models.config import Config
from copilot.models.config import PluginOptions
from random import randrange
from uuid import uuid4
import json
import os

import logging
log = logging.getLogger("copilot.plugins." + __name__)


class Plugin(PluginOptions):

    def __init__(self, byte_dir=None, recompile_rules=False):
        super(PluginOptions, self).__init__()
        log.debug("Initializing suricata plugin.")
        self.name = "suricata"
        self.has_subtarget = False
        self.config_directory = "/tmp/copilot/"
        self.config_file = "copilot-suricata.rules"
        self.config_path = os.path.join(self.config_directory, self.config_file)
        self.bytes_file = os.path.join(self.config_directory, "suricata_raw_rules")
        if not os.path.isfile(self.bytes_file) or recompile_rules is True:
            if byte_dir is None:
                byte_dir = "/bin/copilot/plugins/suricata/rule_snippets"
            elif not os.path.isdir(byte_dir):
                raise ValueError("Byte directory path provided {0}".format(byte_dir) +
                                 " does not exist.")
            self.rebuild_bytes_file(byte_dir)
        self.load_rules()


    def load_rules(self):
        """Load suricata rules from the core byte file.
        """
        rules = {}
        json_data = get_json(self.bytes_file)
        for traffic_type, contents in json_data.iteritems():
            name = contents.get("name", traffic_type)
            target = contents.get("target", None)
            if target is None:
                log.warn("Suricata rule {0} does not have a target.".format(name) +
                         " It will not be added to the available Suricata rules")
                continue
            byte_sequences = contents.get("byte_sequences", [])
            for sequence in byte_sequences:
                action = sequence.get("action", None)
                if action is None:
                    continue
                log.debug("adding target {0} to action {1}".format(action, target))
                rules.setdefault(action, set()).add(target)
        self.rules = rules

    def rebuild_bytes_file(self, byte_dir):
        """Rebuilds the core byte file from files in the byte snippet directory.

        Args:
            byte_dir (str): The path to the byte snippet directory.

        """
        combined_bytes = {}
        for byte_snippet in os.listdir(byte_dir):
            if byte_snippet.endswith(".json"):
                json_data = get_json(os.path.join(byte_dir, byte_snippet))
                for traffic_type, contents in json_data.iteritems():
                    # This base will not overwrite values
                    combined_bytes.setdefault(traffic_type, {})
                    for key, value in contents.iteritems():
                        if type(key) == list:
                            # This is our byte_sequences list
                            for byte_rule in value:
                                # Write all rule dicts in the byte sequence array
                                combined_bytes[traffic_type].setdefault(key, []).append(byte_rule)
                        else:
                            combined_bytes[traffic_type].setdefault(key, value)
        with open(self.bytes_file, "w+") as byte_file:
            # Pretty print the dictionary to the JSON bytes file
            json.dump(combined_bytes, byte_file, sort_keys=True, indent=4, separators=(',', ': '))
            log.debug("rule file created containing the following rules {0}".format(combined_bytes))

def ascii_byte_to_socrata_seq(byte_seq):
    """
    The current Adversary Lab output format is a JSON dictionary with two keys,
    "incoming" and "outgoing", representing the two directions of the
    connection flow. "Incoming" is packets going to the server. "Outgoing"
    is packets originating from the server. Each of these keys has a value
    that is a list of integers. These represent the ASCII byte values for
    the sequence. All sequences are for the first packet of the stream only
    and start at the first byte of that first packet.

    So for instance, HTTP looks like this:
    {"outgoing": [72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48, 32, 79, 75, 13, 10],
    "incoming": [71, 69, 84, 32, 47]}

    This example snippet encodes the above outgoing array from adversary lab to the
    suricata hex-byte format.

    output = [chr(x).encode('hex') for x in outgoing]

    This encodes the output string into the following array.

    [8, 54, 54, 50, 2f, 31, 2e, 31, 20, 32, 30, 30, 20, 4f, 4b, 0d, 0a]

    If you were to encode this array from hex to ASCII the string would be
    a "GET /" request.

    """
    hex_seq = [chr(byte).encode('hex') for byte in byte_seq]
    spaced_hex = " ".join(hex_seq).upper()
    socrata_seq = "|" + spaced_hex + "|"
    return socrata_seq

def build_adversary_rules(name, sequence):
    """Builds Suricata rule pair to match an identified flow.

    These rule pairs use suricata flowbits to match a connection
    based upon an outgoing and incoming byte-sequence pair.
    https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Flow-keywords

    Args:
    out_rule (dict): A dictionary containing information about the intial outgoing packet in a stream to block.
        {'name':'', 'flow_name':'', 'byte_seq':'', 'sid':''}
    in_rule (dict): A dictionary containing information about the incoming packet that responds to the initial outgoing packet in a stream to block.
    """
    out_rule = {}
    out_rule['byte_seq'] = ascii_byte_to_socrata_seq(sequence['outgoing'])
    out_rule['name'] = name
    out_rule['flow_name'] = sequence.get("flow_name", str(uuid4())[-12:])

    in_rule = {}
    in_rule['byte_seq'] = ascii_byte_to_socrata_seq(sequence['incoming'])
    in_rule['name'] = name
    in_rule['flow_name'] = sequence.get("flow_name", str(uuid4())[-12:])


    set_flow_incoming = ''
    # Create an alert for incoming packets (to external server) that match the following rule
    set_flow_incoming += 'alert ip $HOME_NET any ->  $EXTERNAL_NET any '
    set_flow_incoming += '(msg:"COPILOT - Incoming (to server) bytes for {name} identified."; '.format(**in_rule)
    # Match the byte-sequence provided
    set_flow_incoming += 'content:"{byte_seq}"; offset:0; '.format(**in_rule)
    # Set the flow identifier so the second pattern can match
    # Also, don't create an alert here as we have not seen the outgoing packets
    set_flow_incoming += 'flowbits:set,{flow_name}; flowbits:noalert; '.format(**in_rule)
    # Create a random sid from the local use SID allocation
    # SID's for rules created here fall in the 1000000-1999999 range.
    # See: http://doc.emergingthreats.net/bin/view/Main/SidAllocation
    set_flow_incoming += 'sid:{0}; rev:1;) '.format(randrange(1000000,1999999))

    set_flow_outgoing = ''
    # Create an alert for outgoing packets (to client device) that match the following rule
    set_flow_outgoing += 'alert ip $EXTERNAL_NET any ->  any $HOME_NET '
    set_flow_outgoing += '(msg:"COPILOT - Outgoing (to client) bytes for {name} identified."; '.format(**out_rule)
    # Match the byte-sequence provided
    set_flow_outgoing += 'content:"{byte_seq}"; offset:0; '.format(**out_rule)
    # Set the flow identifier so the second pattern can match
    # Also, don't create an alert here as we have not seen the outgoing packets
    set_flow_outgoing += 'flowbits:set,{flow_name}; flowbits:noalert; '.format(**out_rule)
    # Create a random sid from the local use SID allocation
    # SID's for rules created here fall in the 1000000-1999999 range.
    # See: http://doc.emergingthreats.net/bin/view/Main/SidAllocation
    set_flow_outgoing += 'sid:{0}; rev:1;) '.format(randrange(1000000,1999999))

    reject_incoming = ''
    # Create an alert for incoming packets (to external server) that match the following rule
    reject_incoming += 'reject ip $HOME_NET any ->  $EXTERNAL_NET any '
    reject_incoming += '(msg:"COPILOT - Rejected a {name} connection."; '.format(**in_rule)
    # Match the byte-sequence provided
    reject_incoming += 'content:"{byte_seq}"; offset:0; '.format(**in_rule)
    # Only reject packets when the flow identifier above has been set.
    reject_incoming += 'flowbits:isset,{flow_name}; '.format(**in_rule)
    # Create a random sid from the local use SID allocation
    # SID's for rules created here fall in the 1000000-1999999 range.
    # See: http://doc.emergingthreats.net/bin/view/Main/SidAllocation
    reject_incoming += 'sid:{0}; rev:1;) '.format(randrange(1000000,1999999))

    reject_outgoing = ''
    # Create an alert for outgoing packets (to client device) that match the following rule
    reject_outgoing += 'reject ip $EXTERNAL_NET any ->  any $HOME_NET '
    reject_outgoing += '(msg:"COPILOT - Rejected a {name} connection"; '.format(**out_rule)
    # Match the byte-sequence provided
    reject_outgoing += 'content:"{byte_seq}"; offset:0; '.format(**out_rule)
    # Only reject packets when the flow identifier above has been set.
    reject_outgoing += 'flowbits:isset,{flow_name}; '.format(**out_rule)
    # Create a random sid from the local use SID allocation
    # SID's for rules created here fall in the 1000000-1999999 range.
    # See: http://doc.emergingthreats.net/bin/view/Main/SidAllocation
    reject_outgoing += 'sid:{0}; rev:1;) '.format(randrange(1000000,1999999))

    rules = [set_flow_incoming, set_flow_outgoing, reject_incoming, reject_outgoing]
    return rules

def get_json(json_path):
    """Get json data from a file."""
    with open(json_path, "r") as json_file:
        try:
            json_data = json.load(json_file)
        except ValueError as _e:
            log.error("JSON is incorrectly formatted. Could not be loaded.")
            raise ValueError(_e)
    return json_data

def load_rules(rule_path, rule_name):
    json_data = get_json(rule_path)
    rules = make_rules(json_data)

def make_rules(rule_set):
    """ Create a dictionary containing ALL POSSIBLE sucrata rules.

    Args:
        rule_set (dict): Adversary lab rule sets json translated into a dictionary.
    """
    rules = {}
    for traffic_type, contents in rule_set.items():
        name = contents.get("name", traffic_type)
        target = contents.get("target", None)
        byte_sequences = contents.get("byte_sequences", [])

        for sequence in byte_sequences:
            rule_type = sequence.get("rule_type","")
            if rule_type == "adversary labs":
                try:
                    # Add the formatted rule pair
                    rules.setdefault(name, []).append(build_adversary_rules(name, sequence))
                except KeyError:
                    # If either byte_seq in missing we don't want to add to our rules
                    log.info("Rule pair for {0} is missing a byte sequence".format(traffic_type))
            elif rule_type == "raw rule":
                try:
                    rules.setdefault(name, []).append([sequence["rule"]])
                except KeyError:
                    log.info("Rule {0} does not have the required ".format(name) +
                             "rule key and will be skipped")
    return rules


class ConfigWriter(Config):

    def __init__(self):
        log.debug("Creating Suricata Plugin Object.")
        super(ConfigWriter, self).__init__()
        self.config_type = "suricata"
        plugin_dir = os.environ['COPILOT_PLUGINS_DIRECTORY']
        self.rule_path = os.path.abspath(os.path.join(plugin_dir,
                                                       "plugins/suricata/byte_dict.json"))
        self.load_rules()
        self.header = ("# This Suricata rules file is AUTOMATICALLY GENERATED.\n" +
                       "# This file was created by the copilot suricata plugin.\n" +
                       "# Edits to this file will be overwritten without notice.\n" +
                       "# This file is created and deleted as needed.\n")
        log.debug("header of type {0}".format(type(self.header)))
        log.info("Suricata config writer loaded.")

    def load_rules(self):
        log.debug("Loading Suricata rules")
        json_data = get_json(self.rule_path)
        self.suricata_rules = make_rules(json_data)

    def add_rule(self, rule):
        log.debug("Adding Suricata rule")
        target = rule[1]
        if target in self.suricata_rules:
            log.debug("adding rule to reject {0}.".format(rule))
            self._rules.append(self.suricata_rules[target])
        else:
            log.debug("rule to reject {0} not found.".format(rule))

    def write_rule(self, config_file, rule_set):
        log.debug("Writing Rules")
        log.debug("Starting to write rule pair {0}".format(rule_set))
        for rule in rule_set:
            log.debug("writing rule {0} to the config file.".format(rule))
            for sub_rule in rule:
                config_file.write(sub_rule + "\n")
