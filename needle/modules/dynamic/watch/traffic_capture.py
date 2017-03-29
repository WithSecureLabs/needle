from core.framework.module import BackgroundModule


class Module(BackgroundModule):
    meta = {
        'name': 'Title',
        'author': '@Andrea Amendola',
        'description': 'Description',
        'options': (
            ('port', '7575', True, 'port of the service that will handle the captured traffic'),            
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
        
        # Uploading firewall rules
        self.printer.info('Activating firewall rules...')                 
        local_temp_file = self.local_op.build_temp_path_for_file("needle-pfctl.rules", self)
        remote_temp_file = '/etc/needle-pfctl.rules'

        self.local_op.write_file(local_temp_file, 'rdr on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port 9999\n'
                                                  'pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 80\n')
        # Disabling current firewall rules
        #self.device.remote_op.command_blocking('pfctl -d', internal=False)
        self.device.remote_op.upload(local_temp_file, remote_temp_file, recursive=False)

        self.device.remote_op.command_blocking('pfctl -e -f /etc/needle-pfctl.rules', internal=False)
        self.printer.notify('Firewall rules activated.')

        # Running remote port forwarding

        #self.local_op.cat_file(temp_path)



        #self.local_op.command_blocking(cmd,
        
        # Start capture
        #self.printer.info('Starting traffic capture...')
        #cmd = "{bin1} -nn -w - -U -s 0 | {bin2} {ip} {port}".format(bin1=self.device.DEVICE_TOOLS['TCPDUMP'], bin2=self.device.DEVICE_TOOLS['NC'], ip=self.options['ip'], port=self.options['port'])
        #self.device.remote_op.command_background_start(self, cmd, stream=True)        
        return

    def module_kill(self):
        #self.device.remote_op.kill_proc('tcpdump')
        #self.printer.info('Traffic capture stopped.')
        return