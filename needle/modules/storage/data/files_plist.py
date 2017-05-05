from core.framework.module import BaseModule
from core.utils.menu import choose_from_list_data_protection
from core.utils.utils import Utils


class Module(BaseModule):
    meta = {
        'name': 'Plist Files',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'List plist files contained in the app folders, alongside with their Data Protection Class. '
                       'Plus, offers the chance to inspect them with Plutil or to dump them all for local analysis.',
        'options': (
            ('analyze', True, True, 'Prompt to pick one file to analyze'),
            ('dump_all', False, True, 'Retrieve all plist files and convert them to XML'),
            ('silent', True, True, 'Silent mode. Will not print file contents to screen when dumping all files'),
            ('output', True, False, 'Full path of the output folder')
        ),
        'comments': [
            '"DUMP_ALL" will build file names based on each file\'s path (changing the / symbol to the _ symbol)',
            'It will overwrite any existing files in the output directory']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']

    def save_file(self, remote_name, local_name, silent):
        """Convert the plist file to XML and save it locally"""
        # Parse the plist
        self.printer.debug("Dumping content of the file: {}".format(remote_name))
        pl = self.device.remote_op.parse_plist(remote_name)
        # Prepare path
        local_name = 'plist_{}'.format(local_name)
        plist_path = self.local_op.build_output_path_for_file(local_name, self)
        # Print & Save to file
        outfile = str(plist_path) if self.options['output'] else None
        self.print_cmd_output(pl, outfile, silent)

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
            self.printer.error("No Plist files found")
            return

        # Save list
        self.add_issue('Plist files detected', out, 'INVESTIGATE', None)

        # Add data protection class
        self.printer.info("Retrieving data protection classes...")
        retrieved_files = self.device.app.get_dataprotection(out)

        # Analysis
        self.printer.info("The following Plist files have been found:")
        if self.options['analyze']:
            # Show Menu
            remote_name = choose_from_list_data_protection(retrieved_files)
            local_name = self.device.app.convert_path_to_filename(remote_name, self.APP_METADATA)
            # Convert the plist and save it locally
            self.save_file(remote_name, local_name, False)
        else:
            # Only list files, do not prompt the user
            choose_from_list_data_protection(retrieved_files, choose=False)

        # Dump all
        if self.options['dump_all']:
            self.printer.notify('Dumping all plist files...')
            for fname in out:
                remote_name = Utils.escape_path(fname)
                # Convert the plist path to a valid filename
                local_name = self.device.app.convert_path_to_filename(fname, self.APP_METADATA)
                # Convert the plist and save it locally
                self.save_file(remote_name, local_name, self.options['silent'])
