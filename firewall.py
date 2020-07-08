from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.modules.pyretic_switch import ActLikeSwitch
from csv import DictReader
from collections import namedtuple
import os

policy_file = "%s/pyretic/pyretic/examples/firewall-policies.csv" % os.environ[ 'HOME' ]
Policy = namedtuple('Policy', ('mac_0', 'mac_1'))

def main():
    # Read in the policies from the .csv file
    def read_policies (file):
        with open(file, 'r') as f:
            reader = DictReader(f, delimiter = ",")
            policies = {}
            for row in reader:
                policies[row['id']] = Policy(MAC(row['mac_0']), MAC(row['mac_1']))
        return policies

    policies = read_policies(policy_file)

    # Start with a policy that doesn't match any packets
    not_allowed = none

    # Add traffic that isn't allowed
    for policy in policies.itervalues():
        not_allowed = not_allowed | match(srcmac=policy.mac_0, dstmac=policy.mac_1) | match(srcmac=policy.mac_1, dstmac=policy.mac_0)

    # Allowed traffic in terms of not_allowed 
    allowed = ~not_allowed

    # Only send allowed traffic to the mac learning (act_like_switch) logic
    return allowed >> ActLikeSwitch()
