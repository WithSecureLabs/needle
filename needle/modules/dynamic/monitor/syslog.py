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

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Main Execution"""
        self.outfile = self.options['output']
        cmd = '{app} > {out}'.format(app=self.TOOLS_LOCAL['IDEVICESYSLOG'], out=self.outfile)
        self.local_op.command_background_start(cmd)

    def module_kill(self):
        """Code to be run when the user choose to kill the job. Useful for closing running tasks and exporting results"""
        # Stop running process
        self.printer.info('Stopping Syslog monitor...')
        self.local_op.command_background_stop('idevicesyslog')
        # Show output
        self.local_op.cat_file(self.outfile)
        self.printer.info("A copy of the output has been saved at the following location: %s" % self.outfile)
