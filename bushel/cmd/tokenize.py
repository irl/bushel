import sys

from bushel import PluggableCommand
from bushel.documents.directory import DirectoryDocument

def cmd_tokenize(args):
    data = sys.stdin.buffer.read()
    document = DirectoryDocument(data)
    for token in document.tokenize():
        print(token)

class ConsensusCommand(PluggableCommand):
    @staticmethod
    def register_subparser(subparsers):
        parser_consensus = subparsers.add_parser(
            "tokenize", help="Tokenize a directory protocol document")
        parser_consensus.set_defaults(func=cmd_tokenize)

