from random import randrange

from copilot.models.config import Config
from uuid import uuid4
import json
import os

import logging
log = logging.getLogger("copilot.plugins." + __name__)


# BYTE DICT FORMAT: JSON
# { "TYPE":
#         [{"outgoing":[],
#           "incoming":[]}]}


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

def build_rule_pair(out_rule, in_rule):
    """Builds Suricata rule pair to match an identified flow.

    These rule pairs use suricata flowbits to match a connection
    based upon an outgoing and incoming byte-sequence pair.
    https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Flow-keywords

    Args:
    out_rule (dict): A dictionary containing information about the intial outgoing packet in a stream to block.
        {'name':'', 'flow_name':'', 'byte_seq':'', 'sid':''}
    in_rule (dict): A dictionary containing information about the incoming packet that responds to the initial outgoing packet in a stream to block.
    """
    outgoing = ''
    # Create an alert for outgoing packets that match the following rule
    outgoing += 'alert ip any any -> any any '
    outgoing += '(msg:"Outgoing bytes for {name} identified.";'.format(**out_rule)
    # Match the byte-sequence provided
    outgoing += 'content:{byte_seq}; offset:0;'.format(**out_rule)
    # Set the flow identifier so the second pattern can match
    # Also, don't create an alert here as we have not seen the incoming packets
    outgoing += 'flowbits:set{flow_name}; flowbits:noalert;'.format(**out_rule)
    # Create a random sid from the local use SID allocation
    outgoing += 'sid:{sid}; rev:1;)'.format(**out_rule)

    incoming = ''
    # Create an alert for incoming packets that match the following rule
    incoming += 'reject ip any any <- any any '
    incoming += '(msg:"Rejected a {name} connection";'.format(**in_rule)
    # Match the byte-sequence provided
    incoming += 'content:{byte_seq}; offset:0;'.format(**in_rule)
    # Only reject packets when the flow identifier above has been set.
    # Once rejected also unset the flow identifier.
    incoming += 'flowbits:isset,{flow_name}; flowbits:unset,{flow_name};'.format(**in_rule)
    # Create a random sid from the local use SID allocation
    incoming += ' sid:{sid}; rev:1;)'.format(**out_rule)

    return (outgoing, incoming)


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
        name = contents.get("name", str(uuid4())[-12:])
        flow_name = contents.get("flow_name", str(uuid4())[-12:])
        byte_sequences = contents.get("byte_sequences", [])

        for sequence in byte_sequences:
            try:
                _outgoing = {}
                _outgoing['byte_seq'] = ascii_byte_to_socrata_seq(sequence['outgoing'])
                _outgoing['name'] = name
                _outgoing['flow_name'] = flow_name
                # SID's for rules created here fall in the 1000000-1999999 range.
                # See: http://doc.emergingthreats.net/bin/view/Main/SidAllocation
                _outgoing["sid"] = int(sequence.get("sid", randrange(1000000,1999999)))

                _incoming = {}
                _incoming['byte_seq'] = ascii_byte_to_socrata_seq(sequence['incoming'])
                _incoming['name'] = name
                _incoming['flow_name'] = flow_name
                _incoming["sid"] = int(sequence.get("sid", randrange(1000000,1999999)))

                # Add the formatted rule pair
                rules.setdefault(traffic_type, []).append(build_rule_pair(_outgoing, _incoming))

            except KeyError:
                log.debug("Rule pair for {0} is missing a byte sequence".format(traffic_type))
                # If either byte_seq in missing we don't want to add to our rules
                continue
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
            config_file.write(str(rule))
