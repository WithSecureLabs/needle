from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Provisioning Profile',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Inspect the provisioning profile of the application.',
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

