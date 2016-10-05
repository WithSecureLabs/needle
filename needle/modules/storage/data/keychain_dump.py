from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Keychain Dump',
        'author': '@LanciniMarco (@MWRLabs) (modifications by @JoshCGrossman (@tghosth)',
        'description': 'Dump the keychain.',
        'options': (
            ('filter', False, False, 'Filter to apply when dumping the keychain. If empty, the entire keychain will be dumped'),
            ('output', True, True, 'Full path of the output file'),
            ('silent', True, True, 'Silent mode - Will not print file contents to screen'),
        ),
        'comments': [
            'Ensure the screen is unlocked before dumping the keychain']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file(self, "keychain")
        # Setting default filter
        if self.APP_METADATA:
            self.printer.info('Setting filter to: %s (you can change it in options)' % self.APP_METADATA['binary_name'])
            self.options['filter'] = self.APP_METADATA['binary_name']

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Composing the command string
        cmd = '{}'.format(self.device.DEVICE_TOOLS['KEYCHAIN_DUMP'])
        msg = "Dumping the keychain"
        if self.options['filter']:
            grep_args = ' -i -a "{}" -C 10 '.format(self.options['filter'])
            msg += ' with filter: %s' % self.options['filter']
        # Dump Keychain (outputs .plist files)
        self.printer.info(msg)
        self.device.remote_op.command_blocking(cmd)

        # Used to check if any files were found
        files_exist = False

        # Used to check if there was any file content after filtering
        file_content = False

        # For each of the four files which keychain_dump outputs
        for filename in ['cert.plist','genp.plist','inet.plist','keys.plist']:

            # If this file exists
            if self.device.remote_op.file_exist(filename):


                files_exist = True

                # read in the file either with or without the filter
                if self.options['filter']:
                    text = self.device.remote_op.read_file(filename,grep_args)
                else:
                    text = self.device.remote_op.read_file(filename)

                # If the file (or filtered file) is not empty
                if text != []:

                    # append the filename to the output path
                    outfile = '{}_{}.txt'.format(self.options['output'], filename)

                    # Save the file locally (and print to screen if silent is False)
                    self.print_cmd_output(text, outfile, self.options['silent'])
                    file_content=True

                # clean up the dumped keychain file on the device
                self.device.remote_op.file_delete(filename)



        # Warn of error conditions
        if (files_exist == False):
            self.printer.warning('No content found. Ensure the screen is unlocked before dumping the keychain')
        elif (file_content == False):
            self.printer.warning('No content matches the filter. Ensure the screen is unlocked before dumping the keychain')

