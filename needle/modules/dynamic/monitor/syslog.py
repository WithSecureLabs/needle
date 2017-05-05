from core.framework.module import BackgroundModule


class Module(BackgroundModule):
    meta = {
        'name': 'Monitor Syslog',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Monitor the Syslog in background and dump its content.',
        'options': (
            ('output', True, True, 'Full path of the output file'),
            ('filter', False, False, 'Filter to apply when monitoring the syslog. If empty, the entire syslog will be monitored'),
        ),
    }
    PID = None

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BackgroundModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("syslog.txt", self)
        # Setting default filter
        if self.APP_METADATA:
            self.printer.info('Setting filter to: %s (you can change it in options)' % self.APP_METADATA['binary_name'])
            self.options['filter'] = self.APP_METADATA['binary_name']

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
        cmd = '{app}'.format(app=self.device.DEVICE_TOOLS['ONDEVICECONSOLE'])
        if self.options['filter']:
            cmd += ' | grep -i "{flt}"'.format(flt=self.options['filter'])
        cmd += ' > {out}'.format(out=self.path_remote)
        self.device.remote_op.command_background_start(self, cmd)

    def module_kill(self):
        # Stop running process
        self.printer.info('Stopping Syslog monitor...')
        self.device.remote_op.command_background_stop(self.PID)

        # Retrieving output
        self.printer.verbose('Retrieving output...')
        self.device.pull(self.path_remote, self.path_local)

        # Show output
        self.local_op.cat_file(self.path_local)
        self.printer.info("A copy of the output has been saved at the following location: %s" % self.path_local)
        self.add_issue('Syslog', None, 'INVESTIGATE', self.path_local)
