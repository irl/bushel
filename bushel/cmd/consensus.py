import sys

from bushel import PluggableCommand
from bushel.remote.directory import consensus

def cmd_consensus(args):
    sys.stdout.buffer.write(consensus())

class ConsensusCommand(PluggableCommand):
    @staticmethod
    def register_subparser(subparsers):
        parser_consensus = subparsers.add_parser(
            "consensus", help="Fetch a consensus from a directory server")
        parser_consensus.set_defaults(func=cmd_consensus)

