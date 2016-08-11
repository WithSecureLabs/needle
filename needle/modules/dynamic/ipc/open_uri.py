from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Open URI',
        'author': '@HenryHoggard (@MWRLabs)',
        'description': 'Test IPC attacks by launching URI Handlers (e.g., tel://123456789)',
        'options': (
            ('uri', "", True, 'URI to launch, eg tel://123456789 or http://www.google.com/'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Open the URI
        self.printer.notify('Opening URI: %s' % self.options['uri'])
        cmd = '{bin} {uri}'.format(bin=self.device.DEVICE_TOOLS['UIOPEN'], uri=self.options['uri'])
        self.device.remote_op.command_blocking(cmd)
