from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'List Tweaks',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'List all the Tweaks installed using Needle',
        'options': (
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
        self.printer.info("Looking for installed Tweaks...")
        cmd = "{dpkg} -l | grep needle".format(dpkg=self.device.DEVICE_TOOLS['DPKG'])
        out = self.device.remote_op.command_blocking(cmd)
        if out:
            self.printer.notify("The following Tweaks have been found: ")
            self.print_cmd_output(out)
        else:
            self.printer.warning("No Tweaks found.")
