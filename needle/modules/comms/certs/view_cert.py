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
        'comments': ['This script doesn\'t currently verify the validity of the certificate.']
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

        # Start building the cURL command
        cmd = 'curl --insecure -v https://{} '.format(self.options['url'])

        # Add a proxy if relevant
        if self.options['proxy'] is not None:
            cmd += ' -x {} '.format(self.options['proxy'])

        # Use awk to display only the relevant lines from the output
        cmd += " 2>&1 | awk 'BEGIN { cert=0 } /^\* Server certificate:/ { cert=1 } /^\*/ { if (cert) print }'"

        # Run the command and print to screen
        out = self.device.remote_op.command_blocking(cmd)
        self.print_cmd_output(out)