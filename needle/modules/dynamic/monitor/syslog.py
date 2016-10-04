from core.framework.module import BackgroundModule


class Module(BackgroundModule):
    meta = {
        'name': 'Monitor Syslog',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Monitor the Syslog in background and dump its content.',
        'options': (
            ('output', True, True, 'Full path of the output file'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BackgroundModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file(self, "syslog.txt")

    def module_pre(self):
        return BackgroundModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Prepare paths
        self.path_remote = self.device.remote_op.build_temp_path_for_file('syslog')
        self.path_local = self.options['output'] if self.options['output'] else None

        # Build cmd
        cmd = '{app} > {out}'.format(app=self.device.DEVICE_TOOLS['ONDEVICECONSOLE'],
                                     out=self.path_remote)
        self.local_op.command_background_start(cmd)

    def module_kill(self):
        # Stop running process
        self.printer.info('Stopping Syslog monitor...')
        self.local_op.command_background_stop(self.device.DEVICE_TOOLS['ONDEVICECONSOLE'])

        # Retrieving output
        self.printer.verbose('Retrieving output...')
        self.device.pull(self.path_remote, self.path_local)

        # Show output
        self.local_op.cat_file(self.path_local)
        self.printer.info("A copy of the output has been saved at the following location: %s" % self.path_local)
