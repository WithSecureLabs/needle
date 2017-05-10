#!/usr/bin/env python
import argparse
import sys

# Prevent creation of compiled bytecode files
sys.dont_write_bytecode = True

from core.framework import cli
from core.utils.printer import Printer
from core.utils.constants import Constants


# ======================================================================================================================
# Setup command completion and run the CLI
# ======================================================================================================================
def parse_modules(args):
    sep = '#'
    modules = []
    for el in args:
        splitted = el.split(sep)
        modules.append({'module': splitted[0], 'options': splitted[1:]})
    return modules


def launch_cli(args):
    # Instantiate the UI object
    x = cli.CLI(cli.Mode.CLI)
    printer = Printer()
    # Check for and run version check
    if args.check and not x.version_check():
        return

    # ==================================================================================================================
    # PARSE ARGS
    # ==================================================================================================================
    # Run given global commands
    for command in args.global_commands:
        printer.notify('GLOBAL COMMAND => {}'.format(command))
        x.onecmd(command)
    # Set given global options
    for option in args.goptions:
        param = ' '.join(option.split('='))
        x.do_set(param)
    # If requested, show global options and exit
    if args.gshow:
        x.do_show('options')
    # If requested, show modules and exit
    if args.show_modules:
        x.do_show('modules')
    # Load modules
    if args.modules:
        modules = parse_modules(args.modules)
        for m in modules:
            # Load the module
            y = x.do_load(m['module'])
            # Skip if module not successfully loaded
            if not y:
                printer.error('Module loading failed, skipping')
                continue
            printer.notify('MODULE => {}'.format(m['module']))
            # Set given module options
            for option in m['options']:
                param = ' '.join(option.split('='))
                y.do_set(param)
            # Run the module
            y.do_run([])
        # Exit the framework
        y.do_exit(None)
    else:
        # Exit the framework
        x.do_exit(None)

# ======================================================================================================================
# MAIN
# ======================================================================================================================
def main():
    description = '%%(prog)s - %s %s' % (cli.__author__, cli.__email__)
    parser = argparse.ArgumentParser(description=description, version=Constants.VERSION)
    parser.add_argument('-G', help='show available global options', dest='gshow', default=False, action='store_true')
    parser.add_argument('-g', help='set a global option (can be used more than once)', metavar='name=value', dest='goptions', default=[], action='append')
    parser.add_argument('-M', help='show modules', dest='show_modules', default=False, action='store_true')
    parser.add_argument('-C', help='runs a command at the global context', metavar='command', dest='global_commands', default=[], action='append')
    parser.add_argument('-m', help='specify the modules/options (can be used more than once). Example: -m binary/info/metadata -m device/agent_client#COMMAND=OS_VERSION', metavar='modules', dest='modules', default=[], action='append')
    parser.add_argument('--no-check', help='disable version check', dest='check', default=True, action='store_false')
    args = parser.parse_args()
    launch_cli(args)

if __name__ == '__main__':
    main()
