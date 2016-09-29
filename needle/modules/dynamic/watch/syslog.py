from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Syslog Watch',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Watch the syslog in realtime (and save it to file)',
        'options': (
            ('output', True, False, 'Full path of the output file'),
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
        # Build cmd
        cmd = '{app}'.format(app=self.TOOLS_LOCAL['IDEVICESYSLOG'])
        if self.options['output']:
            cmd += ' | tee {}'.format(self.options['output'])
        # Running cmd
        self.printer.notify("Attaching to syslog (CTRL-C to quit)")
        self.local_op.command_interactive(cmd)
