from core.framework.module import BaseModule
from core.device.device import Device
from core.utils.menu import choose_from_list_data_protection, choose_from_list, choose_boolean
from core.utils.utils import Utils
import re, sys

class Module(BaseModule):
    meta = {
        'name': 'MDM Pull',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description':  'Pulls the Effective Configuration from device.',
        'options': (
            ('autosave', False, False, 'Automatically save files.'),
            ('silent', True, False, 'Silent mode. Will not print config to screen.'),
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

    # Format output filename
    def set_output_name(self, remote_file):
        fileName = Utils.extract_filename_from_path(remote_file)
        fileName = 'mdm_pull_{}'.format(fileName)
        return self.local_op.build_output_path_for_file(fileName, self)

    # Save file
    def save_file(self, remote_file, local_file):
        if self.options['autosave']:
            self.device.pull(remote_file, local_file)
        else:
            save = choose_boolean("Would you like to pull ths file?")
            if save: self.device.pull(remote_file, local_file)

        
    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.verbose("Searching for Configuration file...")

        # Find MDM config file locations
        arg = "/var/mobile/Library/ConfigurationProfiles/EffectiveUserSettings.plist"
        cmd = '{bin} {arg}'.format(bin=self.device.DEVICE_TOOLS['FIND'], arg=arg)
        config = self.device.remote_op.command_blocking(cmd)[0].strip()

        if not config:
            self.printer.error("No Configuration files found!")
            return
        self.printer.notify("Found: %s" % config)

        # Parse configuration (and save to variable)
        cmd = '{bin} {arg}'.format(bin=self.device.DEVICE_TOOLS['PLUTIL'], arg=config)
        parsedConfig = ''.join(self.device.remote_op.command_blocking(cmd))

        # Print config data (if not in silent mode)
        if not self.options['silent']:
            print parsedConfig

        # Save file (as both XML and object format)
        outFile = self.set_output_name(config)
        if self.options['autosave'] or choose_boolean("Would you like to save ths file?"):
            self.device.pull(config, outFile)
            self.local_op.write_file(outFile+'.txt', parsedConfig)


