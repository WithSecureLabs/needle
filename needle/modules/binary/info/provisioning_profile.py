from core.framework.module import BaseModule
from core.utils.utils import Utils


class Module(BaseModule):
    meta = {
        'name': 'Provisioning Profile',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Inspect the provisioning profile of the application, then parse the embedded certificate looking for distribution profiles',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
        'comments': ['This module works only on macOS, since it requires the "security" utility',
        ]
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("provisioning_profile", self)

    def _parse_certificate(self, data):
        # Read the plist file
        pl = Utils.plist_read_from_file(data, use_plistlib=True)
        # Extract the Data field of the certificate and store it locally
        cert = pl["DeveloperCertificates"][0].data
        cert_file = self.device.local_op.build_temp_path_for_file("cert", self)
        self.device.local_op.write_file(cert_file, cert)
        # Extract strings and look for the distribution profile
        cmd = "cat {} | strings | grep iPhone".format(cert_file)
        out = self.device.local_op.command_blocking(cmd)[0]
        if out:
            msg = "Distribution Profile found"
            self.printer.notify(msg)
            self.print_cmd_output(out, None)
            self.add_issue('Provisioning Profile', '{}: {}'.format(msg, out), 'INVESTIGATE', None)
        else:
            msg = "No Distribution Profile found"
            self.printer.error(msg)
            self.add_issue('Provisioning Profile', msg, 'HIGH', None)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Preparing paths
        embedded = 'embedded.mobileprovision'
        prov_remote = '{}/{}'.format(self.APP_METADATA['binary_directory'], embedded)
        prov_local = self.device.local_op.build_output_path_for_file(embedded, self)

        # Check if mobileprovision is available
        if not self.device.remote_op.file_exist(prov_remote):
            self.printer.error("{} file not available!".format(embedded))
            self.add_issue('Provisioning Profile', '{} file not available'.format(embedded), 'INVESTIGATE', None)
            return

        # Retrieve the file
        self.printer.debug("Retrieving the {} file...".format(embedded))
        self.device.pull(prov_remote, prov_local)

        # Inspect file
        self.printer.notify("CONTENT")
        cmd = '{bin} cms -D -i {prov}'.format(bin=self.TOOLS_LOCAL['SECURITY'],
                                              prov=prov_local)
        out, err = self.device.local_op.command_blocking(cmd)

        outfile = self.options['output'] if self.options['output'] else None
        self.print_cmd_output(out, outfile)

        # Parse the certificate
        self._parse_certificate(outfile)
