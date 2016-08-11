from core.framework.module import BaseModule
from core.utils.menu import choose_from_list_data_protection


class Module(BaseModule):
    meta = {
        'name': 'Plist Files',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'List plist files contained in the app folders, alongside with their Data Protection Class. '
                       'Plus, offers the chance to inspect them with Plutil',
        'options': (
            ('analyze', True, True, 'Prompt to pick one file to analyze'),
            ('output', True, False, 'Full path of the output file')
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_temp_path_for_file(self, "plist.txt")

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Looking for Plist files...")

        # Compose cmd string
        dirs = [self.APP_METADATA['bundle_directory'], self.APP_METADATA['data_directory']]
        dirs_str = ' '.join(dirs)
        cmd = '{bin} {dirs_str} -type f -name "*.plist"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dirs_str)
        out = self.device.remote_op.command_blocking(cmd)

        # No files found
        if not out:
            self.printer.info("No Plist files found")
            return

        # Add data protection class
        self.printer.info("Retrieving data protection classes...")
        retrieved_files = self.device.app.get_dataprotection(out)

        # Show Menu
        self.printer.info("The following Plist files have been found:")
        if self.options['analyze']:
            option = choose_from_list_data_protection(retrieved_files)
            # Run plutil
            self.printer.info("Dumping content of the file")
            pl = self.device.remote_op.parse_plist(option)
            pl = dict(pl)
            # Print & Save to file
            outfile = self.options['output'] if self.options['output'] else None
            self.print_cmd_output(pl, outfile)
        else:
            # Only list files, do not prompt the user
            choose_from_list_data_protection(retrieved_files, choose=False)
