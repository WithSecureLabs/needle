import socket
import select
import multiprocessing

from core.framework.module import BackgroundModule
from core.utils.constants import Constants


class Module(BackgroundModule):
    meta = {
        'name': 'Force Proxy',
        'author': '@Andrea Amendola (@MWRLabs)',
        'description': 'Redirect device traffic to a specific port on the workstation, allowing to intercept it with a proxy. \
                        It is useful when applications are not respecting the system proxy. \
                        It also allows to intercept any protocol on any port, given a non-HTTP aware proxy is listening to proxy_port.\
                        When DNS poisoning results uneffective (applications communicating directly using IP addresses), this module enables\
                        traffic to be intercepted regardlessly.',
        'options': (
            ('proxy_port', '8080', True,
             'Port of the service that will handle the captured traffic'),
            ('device_port', '9999', True,
             'Loopback port on the device used for remote forwarding'),
            ('outbound_ports', '80,443', True,
             'List of outbuond ports the module has to capture the traffic from. Syntax: <port>[,<port>]*'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def module_pre(self):
        return BackgroundModule.module_pre(self, bypass_app=True)

    def _parse_ports(self, ports):
        ports_string = "{%s}" % ports.rstrip(',')

        return ports_string

    # ==================================================================================================================
    # REMOTE PORT FORWARDING
    # ==================================================================================================================

    def _handler(self, chan, host, port):
        sock = socket.socket()
        try:
            sock.connect((host, port))
        except Exception as e:
            self.printer.error(
                'Forwarding request to %s:%d failed: %r' % (host, port, e))
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

    def _reverse_forward_tunnel(self, server_port, remote_host, remote_port, transport, e):
        transport.request_port_forward('', server_port)
        e.set()

        while True:
            chan = transport.accept(1000)
            if chan is None:
                continue
            # Directing traffic captured from server_port to remote_port on the
            # workstation
            self._handler(chan, remote_host, remote_port)

    def _remote_portforward_start(self, e):

        localhost = "127.0.0.1"        

        client = self.device._connect_ssh()

        self.printer.debug('Now forwarding remote port %d to %s:%d ...' % (
            self.options['device_port'], localhost, self.options['proxy_port']))

        # Activate remote forwarding
        self._reverse_forward_tunnel(self.options['device_port'], localhost, int(
            self.options['proxy_port']), client.get_transport(), e)


    def _portforward_proxy_start(self):

        e = multiprocessing.Event()
       
        self.tunnel = multiprocessing.Process(target=self._remote_portforward_start, args=(e,))
        self.tunnel.start()
        e.wait()

    def _portforward_proxy_stop(self):

        self.tunnel.terminate()

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Main Execution"""

        # Uploading firewall rules
        self.printer.info('Activating firewall rules...')
        self.remote_temp_file = Constants.DEVICE_PATH_IFCTL_RULES
        localhost = "127.0.0.1"

        outbound_ports = self._parse_ports(self.options['outbound_ports'])
        firewall_rules = 'rdr on lo0 inet proto tcp from any to any port {} -> {} port {}\npass out route-to (lo0 {}) inet proto tcp from any to any port {}\n'.format(
            outbound_ports, localhost, self.options['device_port'], localhost, outbound_ports)
        self.device.remote_op.write_file(self.remote_temp_file, firewall_rules)

        self.device.remote_op.command_blocking(
            'pfctl -e -f ' + Constants.DEVICE_PATH_IFCTL_RULES, internal=False)
        self.printer.notify('Firewall rules activated.')

        # Running remote port forwarding
        self.printer.info('Activating port forwarding...')
        self._portforward_proxy_start()
        self.printer.notify('Portforwarding activated.')

    def module_kill(self):
        # Deleting local files
        self.printer.info('Deactivating firewall rules...')

        # Deleting remote files
        self.device.remote_op.file_delete(self.remote_temp_file)

        # Deactivating firewall rules
        self.device.remote_op.command_blocking('pfctl -d', internal=False)
        self.printer.notify('Firewall rules deactivated.')

        # Disabling remote forwarding
        self.printer.info('Deactivating port forwarding...')
        self._portforward_proxy_stop()
        self.printer.notify('Portforwarding deactivated.')
