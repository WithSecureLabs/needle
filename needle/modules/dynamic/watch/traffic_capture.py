import paramiko
import socket
import select

from core.framework.module import BackgroundModule
from multiprocessing import Process


class Module(BackgroundModule):
    meta = {
        'name': 'Title',
        'author': '@Andrea Amendola',
        'description': 'Description',
        'options': (
            ('port', '8080', True,
             'port of the service that will handle the captured traffic'),
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
            
            self._handler(chan, remote_host, remote_port)

    def _forward_to_proxy_intermediate(self):       

        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())

        self.printer.debug('Connecting to ssh host %s:%d ...' % (self.device._ip, self.device._port))
        try:
            client.connect(self.device._ip, self.device._port, username=self.device._username, password=self.device._password)
        except Exception as e:
            self.printer.error('*** Failed to connect to %s:%d: %r' % (self.device._ip, self.device._port, e))            

        self.printer.debug('Now forwarding remote port %d to %s:%d ...' % (9999, '127.0.0.1', 8080))

        self._reverse_forward_tunnel(9999, '127.0.0.1', int(self.options['port']), client.get_transport())        

    def _forward_to_proxy(self):
        
        self.tunnel = Process(target=self._forward_to_proxy_intermediate)
        self.tunnel.start()        

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
        self._forward_to_proxy()
        self.printer.notify('Portforwarding activated.')  
        

        return

    def module_kill(self):
        # Deleting local files
        self.printer.info('Deactivating firewall rules...')        
        self.local_op.delete_temp_file(self.local_temp_file, self)
        
        # Deleting remote files
        self.device.remote_op.file_delete(self.remote_temp_file)

        # Deactivating firewall rules
        self.device.remote_op.command_blocking('pfctl -d', internal=False)
        self.printer.notify('Firewall rules deactivated.')       

        # Disabbling remote forwarding
        self.printer.info('Deactivating port forwarding...')
        #self.tunnel._stop()
        self.tunnel.terminate()
        self.printer.notify('Portforwarding deactivated.')

        return
