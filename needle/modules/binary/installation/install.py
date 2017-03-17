from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Install IPA',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Automatically upload and install an IPA on the device',
        'options': (
            ('ipa', '', True, 'Full path of the IPA to install'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Paths
        src = self.options['ipa']
        dst = self.device.remote_op.build_temp_path_for_file("app.ipa")
        # Upload binary to device
        self.printer.verbose("Uploading binary: %s" % src)
        self.device.remote_op.upload(src, dst)
        # Install
        self.printer.verbose("Installing binary...")
        cmd = "{bin} {app}".format(bin=self.device.DEVICE_TOOLS['IPAINSTALLER'], app=dst)
        self.device.remote_op.command_interactive_tty(cmd)
