from __future__ import print_function
import paramiko
from sshtunnel import SSHTunnelForwarder

from app import App
from remote_operations import RemoteOperations
from agent import NeedleAgent
from ..framework.local_operations import LocalOperations
from ..utils.constants import Constants
from ..utils.menu import choose_from_list
from ..utils.printer import Colors, Printer
from ..utils.utils import Utils, Retry


# ======================================================================================================================
# DEVICE CLASS
# ======================================================================================================================
class Device(object):
    # ==================================================================================================================
    # FRAMEWORK ATTRIBUTES
    # ==================================================================================================================
    # Connection Parameters
    _ip, _port, _agent_port, _username, _password = '', '', '', '', ''
    _tools_local = None
    # Port Forwarding
    _frida_server = None
    _port_forward_ssh, _port_forward_agent = None, None
    # App specific
    _applist, _ios_version = None, None
    # Reference to External Objects
    ssh, agent = None, None
    app, installer = None, None
    local_op, remote_op = None, None
    printer = None
    # On-Device Paths
    TEMP_FOLDER = Constants.DEVICE_PATH_TEMP_FOLDER
    DEVICE_TOOLS = Constants.DEVICE_TOOLS

    # ==================================================================================================================
    # INIT
    # ==================================================================================================================
    def __init__(self, ip, port, agent_port, username, password, pub_key_auth, tools):
        # Setup params
        self._ip = ip
        self._port = port
        self._agent_port = agent_port
        self._username = username
        self._password = password
        self._pub_key_auth = bool(pub_key_auth)
        self._tools_local = tools
        # Init related objects
        self.app = App(self)
        self.local_op = LocalOperations()
        self.remote_op = RemoteOperations(self)
        self.printer = Printer()
        self.agent = NeedleAgent(self)

    # ==================================================================================================================
    # UTILS - USB
    # ==================================================================================================================
    def _portforward_usb_start(self):
        """Setup USB port forwarding with TCPRelay."""
        # Check if the user chose a valid port
        if str(self._port) == '22':
            raise Exception('Chosen port must be different from 22 in order to use USB over SSH')
        # Setup the forwarding
        self.printer.debug('Setting up USB port forwarding on port %s' % self._port)
        cmd = '{app} -t 22:{port}'.format(app=self._tools_local['TCPRELAY'], port=self._port)
        self._port_forward_ssh = self.local_op.command_subproc_start(cmd)

    def _portforward_usb_stop(self):
        """Stop USB port forwarding."""
        self.printer.debug('Stopping USB port forwarding')
        self.local_op.command_subproc_stop(self._port_forward_ssh)

    # ==================================================================================================================
    # UTILS - SSH
    # ==================================================================================================================
    def _connect_ssh(self):
        """Open a new SSH connection using Paramiko."""
        try:
            self.printer.verbose("[SSH] Connecting ({}:{})...".format(self._ip, self._port))
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self._ip, port=self._port, username=self._username, password=self._password,
                        allow_agent=self._pub_key_auth, look_for_keys=self._pub_key_auth)
            self.printer.notify("[SSH] Connected ({}:{})".format(self._ip, self._port))
            return ssh
        except paramiko.AuthenticationException as e:
            raise Exception('Authentication failed when connecting to %s. %s: %s' % (self._ip, type(e).__name__, e.message))
        except paramiko.SSHException as e:
            raise Exception('Connection dropped. Please check your connection with the device, '
                            'and reload the module. %s: %s' % (type(e).__name__, e.message))
        except Exception as e:
            raise Exception('Could not open a connection to %s. %s - %s' % (self._ip, type(e).__name__, e.message))

    def _disconnect_ssh(self):
        """Close the SSH connection, if available."""
        self.printer.verbose("[SSH] Disconnecting...")
        if self.ssh:
            self.ssh.close()

    @Retry()
    def _exec_command_ssh(self, cmd, internal):
        """Execute a shell command on the device, then parse/print output."""
        def hotfix_67():
            # TODO: replace with a more long-term fix
            import time
            timeout = 30
            endtime = time.time() + timeout
            while not stdout.channel.eof_received:
                time.sleep(1)
                if time.time() > endtime:
                    stdout.channel.close()
                    break

        # Paramiko Exec Command
        stdin, stdout, stderr = self.ssh.exec_command(cmd)
        hotfix_67()
        # Parse STDOUT/ERR
        out = stdout.readlines()
        err = stderr.readlines()
        if internal:
            # For processing, don't display output
            if err:
                # Show error and abort run
                err_str = ''.join(err)
                raise Exception(err_str)
        else:
            # Display output
            if out: map(lambda x: print('\t%s' % x, end=''), out)
            if err: map(lambda x: print('\t%s%s%s' % (Colors.R, x, Colors.N), end=''), err)
        return out, err

    # ==================================================================================================================
    # UTILS - AGENT
    # ==================================================================================================================
    def _portforward_agent_start(self):
        """Setup local port forward to enable communication with the Needle server running on the device."""
        self.printer.debug('{} Setting up port forwarding on port {}'.format(Constants.AGENT_TAG, self._agent_port))
        localhost = '127.0.0.1'
        self._port_forward_agent = SSHTunnelForwarder(
            (self._ip, int(self._port)),
            ssh_username=self._username,
            ssh_password=self._password,
            local_bind_address=(localhost, self._agent_port),
            remote_bind_address=(localhost, self._agent_port),
        )
        self._port_forward_agent.start()

    def _portforward_agent_stop(self):
        """Stop local port forwarding for Needle server."""
        self.printer.debug('{} Stopping port forwarding'.format(Constants.AGENT_TAG))
        if self._port_forward_agent:
            self._port_forward_agent.stop()

    def _connect_agent(self):
        self.agent.connect()
        # Ensure the tunnel has been established (especially after auto-reconnecting)
        self.agent.exec_command_agent(Constants.AGENT_CMD_OS_VERSION)

    def _disconnect_agent(self):
        self.agent.disconnect()

    # ==================================================================================================================
    # FRIDA PORT FORWARDING
    # ==================================================================================================================
    def _portforward_frida_start(self):
        """Setup local port forward to enable communication with the Frida server running on the device."""
        self.printer.debug('{} Setting up port forwarding on port {}'.format("[FRIDA]", Constants.FRIDA_PORT))
        localhost = '127.0.0.1'
        self._frida_server = SSHTunnelForwarder(
            (self._ip, int(self._port)),
            ssh_username=self._username,
            ssh_password=self._password,
            local_bind_address=(localhost, Constants.FRIDA_PORT),
            remote_bind_address=(localhost, Constants.FRIDA_PORT),
        )
        self._frida_server.start()

    def _portforward_frida_stop(self):
        """Stop local port forwarding for Frida server."""
        self.printer.debug('{} Stopping port forwarding'.format("FRIDA"))
        if self._frida_server:
            self._frida_server.stop()

    # ==================================================================================================================
    # UTILS - OS
    # ==================================================================================================================
    def _list_apps(self, hide_system_apps=False):
        """Retrieve all the 3rd party apps installed on the device."""
        agent_list = self.agent.exec_command_agent(Constants.AGENT_CMD_LIST_APPS)
        self._applist = Utils.string_to_json(agent_list)
        if hide_system_apps:
            self._applist = {k: v for k, v in self._applist.iteritems() if v["BundleType"] == "User"}

    def select_target_app(self):
        """List all apps installed and let the user choose which one to target."""
        # Show menu to user
        self.printer.notify('Apps found:')
        app_name = choose_from_list(self._applist.keys())
        return app_name

    # ==================================================================================================================
    # EXPOSED COMMANDS
    # ==================================================================================================================
    def is_usb(self):
        """Returns true if using SSH over USB."""
        return self._ip == '127.0.0.1' or self._ip == 'localhost'

    def connect(self):
        """Connect to the device (both SSH and AGENT)."""
        # Using USB, setup port forwarding first
        if self.is_usb():
            self._portforward_usb_start()
            self._portforward_agent_start()
        # Setup channels
        self._connect_agent()
        self.ssh = self._connect_ssh()

    def disconnect(self):
        """Disconnect from the device (both SSH and AGENT)."""
        # Close channels
        self._disconnect_ssh()
        self._disconnect_agent()
        # Using USB, stop port forwarding first
        if self._port_forward_ssh:
            self._portforward_usb_stop()
            self._portforward_agent_stop()

    def setup(self):
        """Create temp folder, and check if all tools are available"""
        # Setup temp folder
        self.printer.debug("Creating temp folder: %s" % self.TEMP_FOLDER)
        self.remote_op.dir_create(self.TEMP_FOLDER)
        # Detect OS version
        if not self._ios_version:
            self._ios_version = self.agent.exec_command_agent(Constants.AGENT_CMD_OS_VERSION).strip()

    def cleanup(self):
        """Remove temp folder from device."""
        self.printer.debug("Cleaning up remote temp folder: %s" % self.TEMP_FOLDER)
        self.remote_op.dir_delete(self.TEMP_FOLDER)

    def shell(self):
        """Spawn a system shell on the device."""
        cmd = 'sshpass -p "{password}" ssh {hostverification} -p {port} {username}@{ip}'.format(password=self._password,
                                                                                                hostverification=Constants.DISABLE_HOST_VERIFICATION,
                                                                                                port=self._port,
                                                                                                username=self._username,
                                                                                                ip=self._ip)
        self.local_op.command_interactive(cmd)

    def pull(self, src, dst):
        """Pull a file from the device."""
        self.printer.info("Pulling: %s -> %s" % (src, dst))
        self.remote_op.download(src, dst)

    def push(self, src, dst):
        """Push a file on the device."""
        self.printer.info("Pushing: %s -> %s" % (src, dst))
        self.remote_op.upload(src, dst)