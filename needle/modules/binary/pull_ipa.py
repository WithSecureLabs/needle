from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Pull IPA',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Decrypt and pull the application's IPA from the device",
        'options': (
            ('output', "", True, 'Full path of the output file'),
            ('decrypt', True, False, 'Set to true to decrypt the IPA before pulling'),
            ('pull_binary', False, False, 'Set to true to pull the application binary as well separately')
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # IPA filename
        fname_ipa = '%s.ipa' % self.APP_METADATA['bundle_id']
        fname_remote = self.device.remote_op.build_temp_path_for_file(fname_ipa)

        if self.options['decrypt']:
            # Decrypt the binary first
            fname_remote = self.device.remote_op.build_temp_path_for_file('decrypted.ipa')
            self.fname_binary = self.device.app.decrypt(self.APP_METADATA)
        else:
            # Recover the IPA
            self.printer.info("Recovering the IPA...")
            cmd = '{bin} -b {bundle} -o {out}'.format(bin=self.device.DEVICE_TOOLS['IPAINSTALLER'],
                                                      bundle=self.APP_METADATA['bundle_id'],
                                                      out=fname_remote)
            self.device.remote_op.command_blocking(cmd)

            # If pulling the binary, unpack the ipa and get the binary link
            if self.options['pull_binary']:
                self.fname_binary = self.device.app.unpack_ipa(self.APP_METADATA, fname_remote)

        fname_local_ipa = self.local_op.build_output_path_for_file(self, fname_remote)

        # Pull file
        self.device.pull(fname_remote, fname_local_ipa)

        # Pull the binary if this has been set.
        if self.options['pull_binary']:
            fname_local_bin = self.local_op.build_output_path_for_file(self, self.fname_binary)
            self.device.pull(self.fname_binary, fname_local_bin)
