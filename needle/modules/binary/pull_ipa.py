from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Pull IPA',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Decrypt and pull the application's IPA from the device",
        'options': (
            ('output', "", False, 'Full path of the output file'),
            ('decrypt', False, False, 'Set to true to pull the decrypted binary')
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # IPA filename
        fname_ipa = '%s.ipa' % self.APP_METADATA['bundle_id']
        fname_remote = self.device.remote_op.build_temp_path_for_file(fname_ipa)
        fname_local  = self.options['output'] if self.options['output'] else self.local_op.build_temp_path_for_file(self, fname_ipa)

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
            out = self.device.remote_op.command_blocking(cmd)

        # Pull file
        self.device.pull(fname_remote, fname_local)
