from core.framework.module import BackgroundModule


class Module(BackgroundModule):
    meta = {
        'name': 'OS Pasteboard',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Monitor the OS Pasteboard and dump its content',
        'options': (
            ('sleep', 5, True, 'Sampling frequency: sleep time, in seconds, between different samples (must be > 1)'),
            ('output', "", True, 'Full path of the output file')
        ),
    }
    PID = None

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BackgroundModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("pasteboard.txt", self)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Main Execution"""
        # Check sleep time
        if int(self.options['sleep']) <= 1:
            self.print_error("Sleep time must be > 1")
            return

        # Remote output file
        self.fname = self.device.remote_op.build_temp_path_for_file("pasteboard")

        # Run command in a thread
        cmd = '{app} {sleep} &> {fname}'.format(app=self.device.DEVICE_TOOLS['PBWATCHER'],
                                                sleep=self.options['sleep'],
                                                fname=self.fname)
        self.device.remote_op.command_background_start(self, cmd)

    def module_kill(self):
        """Code to be run when the user choose to kill the job. Useful for closing running tasks and exporting results"""
        # Kill running process
        self.printer.info('Stopping Pasteboard monitor...')
        self.device.remote_op.command_background_stop(self.PID)

        # Pull output file
        self.printer.verbose("Retrieving output file...")
        outfile = self.options['output']
        self.device.pull(self.fname, outfile)

        # Show output
        self.local_op.cat_file(outfile)
        self.printer.info("A copy of the output has been saved at the following location: %s" % outfile)
        self.add_issue('Content of OS Pasteboard', None, 'INVESTIGATE', outfile)
