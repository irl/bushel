import sys

from bushel import PluggableCommand
from bushel.remote.collector import index

def cmd_collector(args):
    sys.stdout.buffer.write(b"not implemented")

def cmd_index(args):
    sys.stdout.buffer.write(index())

class CollecTorCommand(PluggableCommand):
    @staticmethod
    def register_subparser(subparsers):
        parser_collector = subparsers.add_parser(
            "collector", help="CollecTor Protocol commands")
        collector_subparsers = parser_collector.add_subparsers(help="Subcommands")
        parser_collector.set_defaults(func=cmd_collector)

        parser_index = collector_subparsers.add_parser(
            "index", help="Fetch a CollecTor index")
        parser_index.set_defaults(func=cmd_index)
