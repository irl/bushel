import sys

from bushel import PluggableCommand
from bushel.documents.directory import DirectoryDocument
from bushel.documents.directory import DirectoryDocumentItemError

def cmd_itemize(args):
    data = sys.stdin.buffer.read()
    document = DirectoryDocument(data)
    allowed_errors = []
    if args.forgive:
        for allowed_error in args.forgive.split(","):
            allowed_errors.append(DirectoryDocumentItemError(allowed_error))
    for item in document.items(allowed_errors=allowed_errors):
        print(item)

class ConsensusCommand(PluggableCommand):
    @staticmethod
    def register_subparser(subparsers):
        parser_itemize = subparsers.add_parser(
            "itemize", help="Tokenize a directory protocol document")
        parser_itemize.add_argument("--forgive", metavar="ERRORS",
                                    help=("List of errors to forgive seperated "
                                          "by commas"))
        parser_itemize.set_defaults(func=cmd_itemize)

