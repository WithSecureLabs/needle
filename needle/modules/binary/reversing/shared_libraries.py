from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Shared Libraries',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'List the shared libraries used by the application.',
        'options': (
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.verbose("Analyzing binary for dynamic dependencies...")
        cmd = '{bin} -L {app}'.format(bin=self.device.DEVICE_TOOLS['OTOOL'], app=self.APP_METADATA['binary_path'])
        out = self.device.remote_op.command_blocking(cmd)
        self.print_cmd_output(out)
