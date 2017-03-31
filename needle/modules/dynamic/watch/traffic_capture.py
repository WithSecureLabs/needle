import paramiko
import socket
import select

from core.framework.module import BackgroundModule
from multiprocessing import Process


class Module(BackgroundModule):
    meta = {
        'name': 'Traffic Capture',
        'author': '@Andrea Amendola',
        'description': 'Redirect device traffic (port 80, 443) to a specific port on the workstation',
        'options': (
            ('port', '8080', True,
             'Port of the service that will handle the captured traffic'),
            ('device_port', '9999', True,
             'Loopback port on the device used for remote forwarding'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def module_pre(self):
        return BackgroundModule.module_pre(self, bypass_app=True)


    # ==================================================================================================================
    # REMOTE PORT FORWARDING
    # ==================================================================================================================

    def _handler(self, chan, host, port):
        sock = socket.socket()
        try:
            sock.connect((host, port))
        except Exception as e:
            self.printer.error('Forwarding request to %s:%d failed: %r' % (host, port, e))
            return   
            
        while True:
            r, w, x = select.select([sock, chan], [], [])
            if sock in r:
                data = sock.recv(1024)
                if len(data) == 0:
                    break
                chan.send(data)
            if chan in r:
                data = chan.recv(1024)
                if len(data) == 0:
                    break
                sock.send(data)
        chan.close()
        sock.close()             

    def _reverse_forward_tunnel(self, server_port, remote_host, remote_port, transport):
        transport.request_port_forward('', server_port)
        while True:
            chan = transport.accept(1000)
            if chan is None:
                continue
            # Directing traffic captured from server_port to remote_port on the workstation
            self._handler(chan, remote_host, remote_port)

    def _remote_portforward_start(self):       

        localhost = "127.0.0.1"

        # Create new ssh connection
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        

        self.printer.debug('Connecting to ssh host %s:%d ...' % (self.device._ip, self.device._port))
        try:
            client.connect(self.device._ip, self.device._port, username=self.device._username, password=self.device._password)
        except Exception as e:
            self.printer.error('*** Failed to connect to %s:%d: %r' % (self.device._ip, self.device._port, e))            

        self.printer.debug('Now forwarding remote port %d to %s:%d ...' % (self.options['device_port'], localhost, self.options['port']))

        # Activate remote forwarding
        self._reverse_forward_tunnel(9999, localhost, int(self.options['port']), client.get_transport())        

    def _portforward_proxy_start(self):
        
        self.tunnel = Process(target=self._remote_portforward_start)
        self.tunnel.start()  

    def _portforward_proxy_stop(self):
        
        self.tunnel.terminate()      

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Main Execution"""

        # Uploading firewall rules
        self.printer.info('Activating firewall rules...')
        self.local_temp_file = self.local_op.build_temp_path_for_file("needle-pfctl.rules", self)
        self.remote_temp_file = '/etc/needle-pfctl.rules'

        self.local_op.write_file(self.local_temp_file, 'rdr on lo0 inet proto tcp from any to any port {80,443} -> 127.0.0.1 port 9999\n'
                                 'pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port {80,443}\n')
        
        self.device.remote_op.upload(
            self.local_temp_file, self.remote_temp_file, recursive=False)

        self.device.remote_op.command_blocking('pfctl -e -f /etc/needle-pfctl.rules', internal=False)
        self.printer.notify('Firewall rules activated.')

        # Running remote port forwarding
        self.printer.info('Activating port forwarding...')
        self._portforward_proxy_start()
        self.printer.notify('Portforwarding activated.')  
        

        return

    def module_kill(self):
        # Deleting local files
        #self.printer.info('Deactivating firewall rules...')        
        #self.local_op.delete_temp_file(self.local_temp_file, self)
        
        # Deleting remote files
        self.device.remote_op.file_delete(self.remote_temp_file)

        # Deactivating firewall rules
        self.device.remote_op.command_blocking('pfctl -d', internal=False)
        self.printer.notify('Firewall rules deactivated.')       

        # Disabbling remote forwarding
        self.printer.info('Deactivating port forwarding...')
        self._portforward_proxy_stop
        self.printer.notify('Portforwarding deactivated.')

        return
