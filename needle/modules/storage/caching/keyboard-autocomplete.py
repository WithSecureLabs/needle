from core.framework.module import BaseModule
from core.utils.utils import Utils
import os
import time


class Module(BaseModule):
    meta = {
        'name': 'Keyboard Autocomplete Caching',
        'author': '@zakmaples (@MWRLabs)',
        'description': "This module dumps the contents of the keyboard's autocomplete databases in order to help "
                       "identify if sensitive information input into the application could be cached in the keyboard autocomplete databases.",
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_temp_path_for_file(self, "keyboard-autocomplete-dump.txt")

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        
        # Run strings over files
        self.printer.notify("Running strings over keyboard autocomplete databases")

        #cmd = '{bin} {dirs_str} -type f \( -iname "dynamic-text.dat" -o -iname "dynamic.dat" -o -iname "lexicon.dat" \) -exec strings \{\} \;"' \
        #.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str="/var/mobile/Library/Keyboard/")
        cmd = '{bin} {dirs_str} -type f \( -iname "dynamic-text.dat" -o -iname "dynamic.dat" -o -iname "lexicon.dat" \) -exec {strings} {{}} \;' \
        .format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str="/var/mobile/Library/Keyboard/", strings=self.device.DEVICE_TOOLS['STRINGS'])
        self.printer.notify(cmd)
        out = self.device.remote_op.command_blocking(cmd)

        self.print_cmd_output(out, self.options['output'])
