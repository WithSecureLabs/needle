from core.framework.module import BaseModule
from core.device.device import Device
from core.utils.menu import choose_boolean
from core.utils.utils import Utils
from core.utils.constants import Constants
import re, sys

class Module(BaseModule):
    meta = {
        'name': 'MDM Pull',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description':  'Pulls the configuration plist from device.',
        'options': (
            ('autosave', False, False, 'Automatically save files.'),
            ('output', True, True, 'Full path of the output folder')
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']

    # Format output file_name
    def set_output_name(self, remote_file):
        file_name = Utils.extract_filename_from_path(remote_file)
        file_name = 'mdm_pull_{}'.format(file_name)
        return self.local_op.build_output_path_for_file(file_name, self)

    # Save file
    def save_file(self, remote_file, local_file):
        if self.options['autosave'] or choose_boolean("Would you like to save ths file?"):
            pl = self.device.remote_op.parse_plist(remote_file)
            # Prepare path
            local_file = 'MDM_Pull_{}'.format(local_file)
            plist_path = self.local_op.build_output_path_for_file(local_file, self)
            # Print & Save to file
            outfile = str(plist_path) if self.options['output'] else None
            self.print_cmd_output(pl, outfile, silent)
        
    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.verbose("Searching for Configuration file...")

        # Find MDM config file locations
        arg = Constants.DEVICE_PATH_EFFECTIVE_CONFIG
        cmd = '{bin} {arg}'.format(bin=self.device.DEVICE_TOOLS['FIND'], arg=arg)
        
        try: config = self.device.remote_op.command_blocking(cmd)[0].strip()
        except:
            self.printer.error("No Configuration profile applied!")
            self.printer.warning("Could not find %s" % arg)
            return
        self.printer.notify("Found: %s" % config)

        # Parse and save file!
        self.save_file(config, outFile)