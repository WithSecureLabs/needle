from core.framework.module import BackgroundModule


class Module(BackgroundModule):
    meta = {
        'name': 'Title',
        'author': '@Andrea Amendola',
        'description': 'Description',
        'options': (
            ('ip', '192.168.1.133', True, 'ip of the machine that will capture the traffic'),
            ('port', '7575', True, 'port of the service that will handle the captured traffic'),
            ('program', 'WIRESHARK', True, 'Select the program to use for viewing the captured traffic. Currently supported: WIRESHARK'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def module_pre(self):
        return BackgroundModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Main Execution"""
        # Ensure a valid net traffic viewer has been specified
        self.validate_net_traffic_viewer()

        # Launch net traffic viewer
        self.printer.info('Launching ' + self.net_traffic_viewer +  '...')
        cmd = '{bin} -lnp 7575 | {viewer} -k -i -'.format(bin=self.TOOLS_LOCAL['NC'], viewer=self.net_traffic_viewer)
        self.local_op.command_subproc_start(cmd, piping=True)
        
        # Start capture
        self.printer.info('Starting traffic capture...')
        cmd = "{bin1} -nn -w - -U -s 0 | {bin2} {ip} {port}".format(bin1=self.device.DEVICE_TOOLS['TCPDUMP'], bin2=self.device.DEVICE_TOOLS['NC'], ip=self.options['ip'], port=self.options['port'])
        self.device.remote_op.command_background_start(self, cmd, stream=True)        

    def module_kill(self):
        self.device.remote_op.kill_proc('tcpdump')
        self.printer.info('Traffic capture stopped.')