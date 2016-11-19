from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'View Server Certificate',
        'author': '@tghosth (@JoshCGrossman)',
        'description': 'View details of TLS certificate presented by a specified site.',
        'options': (
            ('url', 'google.com', True, 'Site URL to check (https:// will be added to the front'),
            ('proxy', None, False, 'HTTP proxy to use when checking in the form host:port')
        ),
        'comments': ['This script doesn\'t currently verify the validity of the certificate.',
                     'https://github.com/mwrlabs/needle/pull/62#issuecomment-254037231']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Build the cURL command
        cmd = '{curl} --insecure https://{url} '.format(curl=self.TOOLS_LOCAL['CURL'], url=self.options['url'])
        if self.options['proxy']:
            cmd += ' -x {} '.format(self.options['proxy'])

        # Run the command for the first time to check for errors
        # This command will automatically report if the URL is incorrect or if there is an issue with the proxy
        self.printer.info('Checking for errors...')
        self.device.remote_op.command_blocking('{} --fail --silent --show-error'.format(cmd))

        # Get the certificate
        self.printer.info('Getting the certificate...')

        # Use awk to display only the relevant lines from the output
        cmd += "-v 2>&1 | awk 'BEGIN { cert=0 } /^\* Server certificate:/ { cert=1 } /^\*/ { if (cert) print }'"
        out = self.device.remote_op.command_blocking(cmd)
        self.printer.notify('Certificate information for: {}'.format(self.options['url']))
        self.print_cmd_output(out)
