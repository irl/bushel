import sys

from bushel import PluggableCommand
from bushel.documents.directory import DirectoryDocument

def cmd_itemize(args):
    data = sys.stdin.buffer.read()
    document = DirectoryDocument(data)
    for item in document.items():
        print(item)

class ConsensusCommand(PluggableCommand):
    @staticmethod
    def register_subparser(subparsers):
        parser_itemize = subparsers.add_parser(
            "itemize", help="Tokenize a directory protocol document")
        parser_itemize.set_defaults(func=cmd_itemize)

