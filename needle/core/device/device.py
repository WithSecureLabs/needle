from __future__ import print_function
import paramiko
from sshtunnel import SSHTunnelForwarder

from app import App
from installer import Installer
from remote_operations import RemoteOperations
from ..framework.local_operations import LocalOperations
from ..utils.constants import Constants
from ..utils.menu import choose_from_list
from ..utils.printer import Colors, Printer


# ======================================================================================================================
# DEVICE CLASS
# ======================================================================================================================
class Device(object):
    # ==================================================================================================================
    # FRAMEWORK ATTRIBUTES
    # ==================================================================================================================
    # Connection Parameters
    _ip = ''
    _port = ''
    _username = ''
    _password = ''
    _tools_local = None
    _portforward = None
    _frida_server = None
    _debug_server = None
    # App specific
    _is_iOS8 = False
    _is_iOS9 = False
    _is_iOS7_or_less = False
    _applist = None
    _device_ready = False
    # On-Device Paths
    TEMP_FOLDER = Constants.DEVICE_PATH_TEMP_FOLDER
    DEVICE_TOOLS = Constants.DEVICE_TOOLS
    # Reference to External Objects
    conn = None
    app = None
    installer = None
    local_op = None
    remote_op = None
    printer = None

    # ==================================================================================================================
    # INIT
    # ==================================================================================================================
    def __init__(self, ip, port, username, password, pub_key_auth, tools):
        # Setup params
        self._ip = ip
        self._port = port
        self._username = username
        self._password = password
        self._pub_key_auth = bool(pub_key_auth)
        self._tools_local = tools
        # Init related objects
        self.app = App(self)
        self.installer = Installer(self)
        self.local_op = LocalOperations()
        self.remote_op = RemoteOperations(self)
        self.printer = Printer()

    # ==================================================================================================================
    # UTILS - USB
    # ==================================================================================================================
    def _portforward_usb_start(self):
        """Setup USB port forwarding with TCPRelay."""
        # Check if the user chose a valid port
        if str(self._port) == '22':
            raise Exception('Chosen port must be different from 22 in order to use USB over SSH')
        # Setup the forwarding
        self.printer.verbose('Setting up USB port forwarding on port %s' % self._port)
        cmd = '{app} -t 22:{port}'.format(app=self._tools_local['TCPRELAY'], port=self._port)
        self._portforward = self.local_op.command_subproc_start(cmd)

    def _portforward_usb_stop(self):
        """Stop USB port forwarding."""
        self.printer.verbose('Stopping USB port forwarding')
        self.local_op.command_subproc_stop(self._portforward)

    # ==================================================================================================================
    # UTILS - SSH
    # ==================================================================================================================
    def _connect_ssh(self):
        """Open a new connection using Paramiko."""
        try:
            self.printer.verbose('Setting up SSH connection...')
            self.conn = paramiko.SSHClient()
            self.conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.conn.connect(self._ip, port=self._port, username=self._username, password=self._password,
                              allow_agent=self._pub_key_auth, look_for_keys=self._pub_key_auth)

        except paramiko.AuthenticationException as e:
            raise Exception('Authentication failed when connecting to %s. %s: %s' % (self._ip, type(e).__name__, e.message))
        except paramiko.SSHException as e:
            raise Exception('Connection dropped. Please check your connection with the device, '
                            'and reload the module. %s: %s' % (type(e).__name__, e.message))
        except Exception as e:
            raise Exception('Could not open a connection to %s. %s - %s' % (self._ip, type(e).__name__, e.message))

    def _disconnect_ssh(self):
        """Close the connection, if available."""
        if self.conn:
            self.conn.close()

    def _exec_command_ssh(self, cmd, internal):
        """Execute a shell command on the device, then parse/print output."""
        # Paramiko Exec Command
        stdin, stdout, stderr = self.conn.exec_command(cmd)
        # Parse STDOUT/ERR
        out = stdout.read().decode('iso-8859-1').split('\n')
        out = filter(None, out)
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
    # FRIDA PORT FORWARDING
    # ==================================================================================================================
    def _portforward_frida_start(self):
        """Setup local port forward to enable communication with the Frida server running on the device"""
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
        """Stop local port forwarding"""
        if self._frida_server:
            self._frida_server.stop()

    # ==================================================================================================================
    # LLDB PORT FORWARDING
    # ==================================================================================================================
    def _portforward_debug_start(self):
        """Setup local port forward to enable communication with the debug server running on the device"""
        localhost = '127.0.0.1'
        self._debug_server = SSHTunnelForwarder(
            (self._ip, int(self._port)),
            ssh_username=self._username,
            ssh_password=self._password,
            local_bind_address=(localhost, Constants.DEBUG_PORT),
            remote_bind_address=(localhost, Constants.DEBUG_PORT),
        )
        self._debug_server.start()

    def _portforward_debug_stop(self):
        """Stop local port forwarding"""
        if self._debug_server:
            self._debug_server.stop()

    # ==================================================================================================================
    # UTILS - OS
    # ==================================================================================================================
    def _detect_ios_version(self):
        """Detect the iOS version running on the device."""
        if self.remote_op.file_exist(Constants.DEVICE_PATH_APPLIST_iOS8):
            self._is_iOS8 = True
        elif self.remote_op.file_exist(Constants.DEVICE_PATH_APPLIST_iOS9):
            self._is_iOS9 = True
        else: self._is_iOS7_or_less = True

    def _list_apps(self):
        """List all the 3rd party apps installed on the device."""

        def list_iOS_7():
            raise Exception('Support for iOS < 8 not yet implemented')

        def list_iOS_89(applist):
            # Refresh UICache in case an app was installed after the last reboot
            self.printer.verbose("Refreshing list of installed apps...")
            self.remote_op.command_blocking('/bin/su mobile -c /usr/bin/uicache', internal=True)
            # Parse plist file
            pl = self.remote_op.parse_plist(applist)
            self._applist = pl["User"]

        # Dispatch
        self._detect_ios_version()
        if self._is_iOS8: list_iOS_89(Constants.DEVICE_PATH_APPLIST_iOS8)
        elif self._is_iOS9: list_iOS_89(Constants.DEVICE_PATH_APPLIST_iOS9)
        else: list_iOS_7()

    def select_target_app(self):
        """List all 3rd party apps installed and let the user choose which one to target"""
        self._list_apps()
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
        """Connect to the device."""
        if self.is_usb():
            # Using SSH over USB, setup port forwarding first
            self._portforward_usb_start()
        # Connect
        self._connect_ssh()

    def disconnect(self):
        """Disconnect from the device."""
        if self._portforward:
            # Using SSH over USB, stop port forwarding
            self._portforward_usb_stop()
        self._disconnect_ssh()

    def setup(self, install_tools=True):
        """Create temp folder, and check if all tools are available"""
        # Setup temp folder
        self.printer.verbose("Creating temp folder: %s" % self.TEMP_FOLDER)
        self.remote_op.dir_create(self.TEMP_FOLDER)
        # Install tools
        if install_tools:
            if not self._device_ready:
                self.printer.info("Configuring device...")
                self._device_ready = self.installer.configure()
        else:
            self._device_ready = True

    def cleanup(self):
        """Remove temp folder from device."""
        self.printer.verbose("Cleaning up temp folder: %s" % self.TEMP_FOLDER)
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
