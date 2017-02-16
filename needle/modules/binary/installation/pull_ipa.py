from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Pull IPA',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Decrypt and pull the application's IPA from the device",
        'options': (
            ('output', "", True, 'Full path of the output file'),
            ('decrypt', True, False, 'Set to True to decrypt the IPA before pulling'),
            ('pull_binary', False, False, 'Set to True to pull the application binary as well separately')
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        fname_ipa = '%s.ipa' % self.APP_METADATA['bundle_id'] if self.APP_METADATA else 'app.ipa'
        self.options['output'] = self.local_op.build_output_path_for_file(fname_ipa, self)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # IPA filename
        fname_ipa = '%s.ipa' % self.APP_METADATA['bundle_id']
        fname_remote = self.device.remote_op.build_temp_path_for_file(fname_ipa)
        fname_local_ipa = self.options['output']

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

        # Pull file
        self.device.pull(fname_remote, fname_local_ipa)

        # Pull the binary if this has been set.
        if self.options['pull_binary']:
            self.printer.info("Recovering the binary...")
            self.fname_binary = self.device.app.unpack_ipa(self.APP_METADATA, fname_remote)
            fname_local_bin = self.local_op.build_output_path_for_file(self.fname_binary, self)
            self.device.pull(self.fname_binary, fname_local_bin)
