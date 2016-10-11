from core.framework.module import BackgroundModule


class Module(BackgroundModule):
    meta = {
        'name': 'Monitor File changes',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Monitor the app data folder and keep track of modified files',
        'options': (
            ('output', True, False, 'Full path of the output file'),
            ('folder', "", True, 'The folder to monitor (leave empty to use the app Data directory)'),
        ),
    }
    PID = None

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BackgroundModule.__init__(self, params)
        # Setting defaults
        self.options['output'] = self.local_op.build_output_path_for_file(self, "modified_files.txt")

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Main Execution"""
        # Determining folder to track
        if not self.options['folder']:
            self.options['folder'] = self.APP_METADATA['data_directory']

        # Remote output file
        self.fname = self.device.remote_op.build_temp_path_for_file("fsmon")

        # Run command in a thread
        self.printer.notify('Monitoring: %s' % self.options['folder'])
        cmd = '{app} {flt} &> {fname}'.format(app=self.device.DEVICE_TOOLS['FSMON'],
                                              flt=self.options['folder'],
                                              fname=self.fname)
        self.device.remote_op.command_background_start(self, cmd)


    def module_kill(self):
        """Code to be run when the user choose to kill the job. Useful for closing running tasks and exporting results"""
        # Kill running process
        self.device.remote_op.command_background_stop(self.PID)

        # Pull output file
        self.printer.info("Retrieving output file...")
        outfile = self.options['output']
        self.device.pull(self.fname, outfile)

        # Show output
        self.local_op.cat_file(outfile)
        self.printer.info("A copy of the output has been saved at the following location: %s" % outfile)
