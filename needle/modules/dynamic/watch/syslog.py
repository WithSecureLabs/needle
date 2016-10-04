from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Syslog Watch',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Watch the syslog in realtime (and save it to file)',
        'options': (
            ('output', '', False, 'Full path of the output file'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file(self, "syslog.txt")

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Prepare paths
        path_remote = self.device.remote_op.build_temp_path_for_file('syslog')
        path_local = self.options['output'] if self.options['output'] else None

        # Build cmd
        cmd = '{app}'.format(app=self.device.DEVICE_TOOLS['ONDEVICECONSOLE'])
        if path_local:
            cmd += ' | tee {}'.format(path_remote)

        # Running cmd
        self.printer.notify("Attaching to syslog (CTRL-C to quit)")
        self.device.remote_op.command_interactive_tty(cmd)

        # Retrieving output
        if path_local:
            self.printer.verbose('Retrieving output...')
            self.device.pull(path_remote, path_local)
