from core.framework.module import BaseModule
from core.utils.utils import Utils


class Module(BaseModule):
    meta = {
        'name': 'Keychain Dump',
        'author': '@LanciniMarco (@MWRLabs) (modifications by @tghosth (@JoshCGrossman))',
        'description': 'Dump the keychain.',
        'options': (
            ('filter', '', False, 'Filter to apply when analyzing. If empty, the entire keychain file will be shown'),
            ('output', True, True, 'Full path of the output folder'),
        ),
        'comments': [
            'Ensure the screen is unlocked before dumping the keychain'
        ]
    }

    KEYCHAIN_PLISTS = ['cert.plist', 'genp.plist', 'inet.plist', 'keys.plist']
    LOCAL_PLISTS = []

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']
        # Setting default filter
        if self.APP_METADATA:
            self.printer.info('Setting filter to: %s (you can change it in options)' % self.APP_METADATA['binary_name'])
            self.options['filter'] = self.APP_METADATA['binary_name']

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    def retrieve_files(self):
        if not self.options['output']:
            self.options['output'] = self._global_options['output_folder']
        for fp in self.KEYCHAIN_PLISTS:
            # Prepare path
            temp_name = 'keychain_{}'.format(fp)
            local_name = self.local_op.build_output_path_for_file(temp_name, self)
            self.LOCAL_PLISTS.append(local_name)
            # Save to file
            self.device.pull(fp, local_name)
            # Move remote file to temp folder
            remote_temp = self.device.remote_op.build_temp_path_for_file(fp)
            self.device.remote_op.file_move(fp, remote_temp)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Dump Keychain (outputs .plist files)
        self.printer.info("Dumping the keychain...")
        cmd = '{}'.format(self.device.DEVICE_TOOLS['KEYCHAIN_DUMP'])
        self.device.remote_op.command_blocking(cmd)

        # Parse dumped plist files and merge them into a single data structure
        self.printer.info("Parsing the content...")
        parsed = [self.device.remote_op.parse_plist(item) for item in self.KEYCHAIN_PLISTS]
        flatten = []
        for el in parsed: flatten += el

        # Apply filter
        self.printer.info('Applying filter: {}'.format(self.options['filter']))
        if self.options['filter']:
            expected = [item for item in flatten if self.options['filter'].lower() in item['agrp'].lower()]
        else:
            expected = flatten

        # Retrieve dumped plist files
        self.printer.verbose("Retrieving dumped plist files...")
        self.retrieve_files()

        # Print result
        if expected:
            self.printer.notify("The following content has been dumped (and matches the filter):")
            local_out = self.local_op.build_output_path_for_file('keychain_output', self)
            self.print_cmd_output(expected, local_out)
            self.add_issue('Keychain items detected ({})'.format(len(expected)), None, 'INVESTIGATE', local_out)
        else:
            self.printer.warning('No content found. Try to relax the filter (if applied) and ensure the screen is unlocked before dumping the keychain')
