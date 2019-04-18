import sys

from bushel import PluggableCommand
from bushel.directory.document import DirectoryDocument
from bushel.directory.document import DirectoryDocumentItemError
from bushel.directory.remote import consensus
from bushel.directory.remote import detached_signature

def cmd_dir(args):
    sys.stdout.buffer.write(b"not implemented")

def cmd_consensus(args):
    sys.stdout.buffer.write(detached_signature())

def cmd_consensus(args):
    sys.stdout.buffer.write(consensus())

def cmd_itemize(args):
    data = sys.stdin.buffer.read()
    document = DirectoryDocument(data)
    allowed_errors = []
    if args.forgive:
        for allowed_error in args.forgive.split(","):
            allowed_errors.append(DirectoryDocumentItemError(allowed_error))
    for item in document.items(allowed_errors=allowed_errors):
        print(item)

def cmd_tokenize(args):
    data = sys.stdin.buffer.read()
    document = DirectoryDocument(data)
    for token in document.tokenize():
        print(token)

class DirCommand(PluggableCommand):
    @staticmethod
    def register_subparser(subparsers):
        parser_dir = subparsers.add_parser(
            "dir", help="Tor Directory Protocol commands")
        dir_subparsers = parser_dir.add_subparsers(help="Subcommands")
        parser_dir.set_defaults(func=cmd_dir)

        parser_consensus = dir_subparsers.add_parser(
            "consensus", help="Fetch a consensus from a directory server")
        parser_consensus.set_defaults(func=cmd_consensus)

        parser_detached_signature = dir_subparsers.add_parser(
            "detached-signature", help="Fetch detached signatures from a directory server (next)")
        parser_detached_signature.set_defaults(func=cmd_consensus)

        parser_itemize = dir_subparsers.add_parser(
            "itemize", help="Tokenize a directory protocol document")
        parser_itemize.add_argument("--forgive", metavar="ERRORS",
                                    help=("List of errors to forgive seperated "
                                          "by commas"))
        parser_itemize.set_defaults(func=cmd_itemize)

        parser_tokenize = dir_subparsers.add_parser(
            "tokenize", help="Tokenize a directory protocol document")
        parser_tokenize.set_defaults(func=cmd_tokenize)
