# PSPTool - Display, extract and manipulate PSP firmware inside UEFI images
# Copyright (C) 2019 Christian Werling, Robert Buhren
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys

from .psptool import PSPTool
from .utils import ObligingArgumentParser, print_warning

from argparse import RawTextHelpFormatter, SUPPRESS


def main():
    # CLI stuff to create a PSPTool object and interact with it
    parser = ObligingArgumentParser(description='Display, extract, and manipulate AMD PSP firmware inside BIOS ROMs.\n'
                                                'Note: psptool2 is a rewrite of psptool focussing on usage as a \n'
                                                '      Python package. Please use (legacy) \'psptool\' for advanced CLI'
                                                ' usage.',
                                    formatter_class=RawTextHelpFormatter, add_help=False)

    parser.add_argument('file', help='Binary file to be parsed for PSP firmware (usually 16MB in size)')
    parser.add_argument('-h', '--help', action='help', help='Show this help message and exit.\n\n')
    parser.add_argument('-v', '--verbose', help='Increase output verbosity', action='store_true')

    parser.add_argument('-d', '--directory-index', help=SUPPRESS, type=int)
    parser.add_argument('-e', '--entry-index', help=SUPPRESS, type=int)
    parser.add_argument('-s', '--subfile', help=SUPPRESS)
    parser.add_argument('-o', '--outfile', help=SUPPRESS)

    action = parser.add_mutually_exclusive_group(required=False)

    action.add_argument('-E', '--entries', help='\n'.join([
        'Default: Parse and display PSP firmware entries.',
        '']), action='store_true')

    action.add_argument('-R', '--replace-entry', help='\n'.join([
        'Copy a new entry into the ROM file and update metadata accordingly.',
        '-d idx -e idx -s subfile -o outfile',
        '',
        '-d idx:  specifies directory_index',
        '-e idx:  specifies entry_index',
        '-s file: specifies subfile (i.e. the new entry contents)',
        '-o file: specifies outfile',
        '']), action='store_true')

    args = parser.parse_args()
    psp = PSPTool.from_file(args.file, verbose=args.verbose)

    if args.replace_entry:
        if args.directory_index is not None and args.entry_index is not None and args.subfile is not None \
                and args.outfile is not None:
            with open(args.subfile, 'rb') as f:
                    sub_binary = f.read()

            entry = psp.blob.directories[args.directory_index].entries[args.entry_index]
            entry.move_buffer(entry.get_address(), len(sub_binary))
            entry.set_bytes(0, len(sub_binary), sub_binary)

            psp.to_file(args.outfile)
        else:
            parser.print_help(sys.stderr)
    else:
        psp.ls()


if __name__ == '__main__':
    main()