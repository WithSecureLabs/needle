import paramiko
import threading
import socket
import select
from core.framework.module import BackgroundModule


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

    def _portforward_proxy_start(self):
        """Setup port forward to enable communication with the proxy server running on the workstation"""
        localhost = '127.0.0.1'
        self._proxy_server = SSHTunnelForwarder(
            (self.device._ip, int(self.device._port)),
            ssh_username=self.device._username,
            ssh_password=self.device._password,
            local_bind_address=(localhost, 9999),
            remote_bind_address=(localhost, 8080),
        )
        self._proxy_server.start()

    def _portforward_proxy_stop(self):
        """Stop local port forwarding"""
        if self._proxy_server:
            self._proxy_server.stop()

    # ==================================================================================================================
    # REMOTE PORT FORWARDING
    # ==================================================================================================================

    def _handler(self, chan, host, port):
        sock = socket.socket()
        try:
            sock.connect((host, port))
        except Exception as e:
            self.printer.info('Forwarding request to %s:%d failed: %r' % (host, port, e))
            return   
    
        self.printer.info('Connected!  Tunnel open %r -> %r -> %r' % (chan.origin_addr,
                                                            chan.getpeername(), (host, port)))
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
        self.printer.info('Tunnel closed from %r' % (chan.origin_addr,))     

    def _reverse_forward_tunnel(self, server_port, remote_host, remote_port, transport):
        transport.request_port_forward('', server_port)
        while True:
            chan = transport.accept(1000)
            if chan is None:
                continue
            thr = threading.Thread(target=self._handler, args=(chan, remote_host, remote_port))
            thr.setDaemon(True)
            thr.start()

    def forward_to_proxy(self):
        g_verbose = True
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy())

        self.printer.info('Connecting to ssh host %s:%d ...' % (self.device._ip, self.device._port))
        try:
            client.connect(self.device._ip, self.device._port, username=self.device._username, password=self.device._password)
        except Exception as e:
            print('*** Failed to connect to %s:%d: %r' % (sself.device._ip, self.device._port, e))
            sys.exit(1)

        self.printer.info('Now forwarding remote port %d to %s:%d ...' % (9999, '127.0.0.1', 8080))

        try:
            self._reverse_forward_tunnel(9999, '127.0.0.1', 8080, client.get_transport())
        except KeyboardInterrupt:
            print('C-c: Port forwarding stopped.')

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Main Execution"""

        # Uploading firewall rules
        self.printer.info('Activating firewall rules...')
        self.local_temp_file = self.local_op.build_temp_path_for_file("needle-pfctl.rules", self)
        self.remote_temp_file = '/etc/needle-pfctl.rules'

        self.local_op.write_file(self.local_temp_file, 'rdr on lo0 inet proto tcp from any to any port 80 -> 127.0.0.1 port 9999\n'
                                 'pass out route-to (lo0 127.0.0.1) inet proto tcp from any to any port 80\n')
        
        self.device.remote_op.upload(
            self.local_temp_file, self.remote_temp_file, recursive=False)

        self.device.remote_op.command_blocking('pfctl -e -f /etc/needle-pfctl.rules', internal=False)
        self.printer.notify('Firewall rules activated.')

        # Running remote port forwarding
        self.printer.info('Activating port forwarding...')
        self.forward_to_proxy()
        self.printer.notify('Portforwarding activated.')
        
        #cmd = "sshpass -p {ssh_pass} ssh -R 9999:127.0.0.1:8080 root@{device_ip}".format(ssh_pass=self.device._password, device_ip=self.device._ip)
        #self.tunnel = self.local_op.command_background_start(cmd)

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

        # Stopping remote port forwarding
        #self.printer.info('Deactivating port forwarding...')
        #self._portforward_proxy_stop()
        #self.printer.notify('Portforwarding deactivated.')

        #self.command_background_stop('sshpass')

        return
