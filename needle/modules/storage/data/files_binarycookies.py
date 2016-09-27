from core.framework.module import BaseModule
from core.utils.menu import choose_from_list_data_protection
from core.utils.utils import Utils


class Module(BaseModule):
    meta = {
        'name': 'Binary Cookies Files',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'List Binary Cookies files contained in the app folders, alongside with their Data Protection Class.'
                       'Plus, offers the chance to pull and inspect them with BinaryCookieReader',
        'options': (
            ('analyze', True, True, 'Prompt to pick one file to analyze'),
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Looking for Binary Cookies files...")

        # Compose cmd string
        dirs = [self.APP_METADATA['bundle_directory'], self.APP_METADATA['data_directory']]
        dirs_str = ' '.join(dirs)
        cmd = '{bin} {dirs_str} -type f -name "*binarycookies"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dirs_str)
        out = self.device.remote_op.command_blocking(cmd)

        # No files found
        if not out:
            self.printer.info("No Binary Cookies files found")
            return

        # Add data protection class
        self.printer.info("Retrieving data protection classes...")
        retrieved_files = self.device.app.get_dataprotection(out)

        # Show Menu
        self.printer.info("The following Binary Cookies files have been found:")
        if self.options['analyze']:
            option = choose_from_list_data_protection(retrieved_files)
            # Pull file
            fname = Utils.extract_filename_from_path(option)
            temp_file = self.local_op.build_output_path_for_file(self, fname)
            self.device.pull(option, temp_file)
            # Analyze it with BinaryCookieReader
            cmd = 'python {bin} {temp_file}'.format(bin=self.TOOLS_LOCAL['BINARYCOOKIEREADER'], temp_file=temp_file)
            self.local_op.command_interactive(cmd)
            # Delete file
            self.local_op.delete_temp_file(self, fname)
        else:
            # Only list files, do not prompt the user
            choose_from_list_data_protection(retrieved_files, choose=False)
