import os
import time
import threading
import subprocess
import plistlib

from ..utils.constants import Constants
from ..utils.utils import Utils


class RemoteOperations(object):
    # ==================================================================================================================
    # INIT
    # ==================================================================================================================
    def __init__(self, device):
        self._device = device

    # ==================================================================================================================
    # FILES
    # ==================================================================================================================
    def file_exist(self, path):
        path = Utils.escape_path(path)
        cmd = 'if [ -f %s ]; then echo "yes"; else echo "no" ; fi' % path
        out = self.command_blocking(cmd, internal=True)
        res = out[0] if type(out) is list else out
        if res.strip() == "yes": return True
        else: return False

    def file_create(self, path):
        path = Utils.escape_path(path)
        if not self.file_exist(path):
            cmd = 'touch %s' % path
            self.command_blocking(cmd)

    def file_delete(self, path):
        path = Utils.escape_path(path)
        if self.file_exist(path):
            cmd = 'rm %s 2> /dev/null' % path
            self.command_blocking(cmd)

    def file_copy(self, src, dst):
        src, dst = Utils.escape_path(src), Utils.escape_path(dst)
        cmd = "cp {} {}".format(src, dst)
        self.command_blocking(cmd)

    def file_move(self, src, dst):
        src, dst = Utils.escape_path(src), Utils.escape_path(dst)
        cmd = "mv {} {}".format(src, dst)
        self.command_blocking(cmd)

    # ==================================================================================================================
    # DIRECTORIES
    # ==================================================================================================================
    def dir_exist(self, path):
        path = Utils.escape_path(path)
        cmd = 'if [ -d %s ]; then echo "yes"; else echo "no" ; fi' % path
        out = self.command_blocking(cmd, internal=True)
        res = out[0] if type(out) is list else out
        if res.strip() == "yes": return True
        else: return False

    def dir_create(self, path):
        path = Utils.escape_path(path)
        if not self.dir_exist(path):
            cmd = 'mkdir %s' % path
            self.command_blocking(cmd)

    def dir_delete(self, path, force=False):
        def delete(path):
            cmd = 'rm -rf %s 2> /dev/null' % path
            self.command_blocking(cmd)
        path = Utils.escape_path(path)
        if force: delete(path)
        elif self.dir_exist(path): delete(path)

    def dir_list(self, path, recursive=False):
        path = Utils.escape_path(path)
        opts = ''
        if recursive: opts = '-alR'
        cmd = 'ls {opts} {path}'.format(opts=opts, path=path)
        return self.command_blocking(cmd)

    def dir_reset(self, path):
        if self.dir_exist(path): self.dir_delete(path)
        self.dir_create(path)

    # ==================================================================================================================
    # COMMANDS
    # ==================================================================================================================
    def command_blocking(self, cmd, internal=True):
        """Run a blocking command: wait for its completion before resuming execution."""
        self._device.printer.debug('[REMOTE CMD] Remote Command: %s' % cmd)
        out, err = self._device._exec_command_ssh(cmd, internal)
        if type(out) is tuple: out = out[0]
        return out

    def command_interactive(self, cmd):
        """Run a command which requires an interactive shell."""
        self._device.printer.debug("[REMOTE CMD] Remote Interactive Command: %s" % cmd)
        cmd = 'sshpass -p "{password}" ssh {hostverification} -p {port} -t {username}@{ip} "{cmd}"'.format(password=self._device._password,
                                                                                                           hostverification=Constants.DISABLE_HOST_VERIFICATION,
                                                                                                           port=self._device._port,
                                                                                                           username=self._device._username,
                                                                                                           ip=self._device._ip,
                                                                                                           cmd=cmd)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = proc.stdout.read(), proc.stderr.read()
        return stdout, stderr

    def command_interactive_tty(self, cmd):
        """Run a command in a full TTY shell."""
        self._device.printer.debug("[REMOTE CMD] Remote Interactive TTY Command: %s" % cmd)
        cmd = 'sshpass -p "{password}" ssh {hostverification} -p {port} -t {username}@{ip} "{cmd}"'.format(password=self._device._password,
                                                                                                           hostverification=Constants.DISABLE_HOST_VERIFICATION,
                                                                                                           port=self._device._port,
                                                                                                           username=self._device._username,
                                                                                                           ip=self._device._ip,
                                                                                                           cmd=cmd)
        out = subprocess.call(cmd, shell=True)
        return out

    def command_background_start(self, module, cmd):
        """Run a background command: run it in a new thread and resume execution immediately."""
        self._device.printer.debug('[REMOTE CMD] Remote Background Command: %s' % cmd)

        def daemon(module, cmd):
            """Daemon used to run the command so to avoid blocking the UI"""
            # Run command
            cmd += ' & echo $!'
            out = self.command_blocking(cmd)
            # Parse PID of the process
            try:
                pid = out[0].strip()
            except Exception as e:
                module.printer.error("Error while parsing process PID. Skipping")
                pid = None
            module.PID = pid
            module.printer.info("Monitoring in background...Kill this process when you want to see the dumped content")

        # Run command in a thread
        d = threading.Thread(name='daemon', target=daemon, args=(module, cmd))
        d.setDaemon(True)
        d.start()
        time.sleep(2)

    def command_background_stop(self, pid):
        """Stop a running background command."""
        self._device.printer.debug('[REMOTE CMD] Stopping Remote Background Command [pid: %s]' % pid)
        cmd = "kill %s" % pid
        self.command_blocking(cmd)

    def kill_proc(self, procname):
        """Kill the running process with the specified name."""
        self._device.printer.debug('[REMOTE CMD] Killing process [name: %s]' % procname)
        cmd = 'killall -9 "%s"' % procname
        self.command_blocking(cmd)

    # ==================================================================================================================
    # DOWNLOAD/UPLOAD
    # ==================================================================================================================
    def download(self, src, dst, recursive=False):
        """Download a file from the device."""
        src, dst = Utils.escape_path_scp(src), Utils.escape_path_scp(dst)
        self._device.printer.debug("Downloading: %s -> %s" % (src, dst))

        cmd = 'sshpass -p "{password}" scp {hostverification} -P {port}'.format(password=self._device._password,
                                                                                hostverification=Constants.DISABLE_HOST_VERIFICATION,
                                                                                port=self._device._port)
        if recursive: cmd += ' -r'
        cmd += ' {username}@{ip}:{src} {dst}'.format(username=self._device._username,
                                                    ip=self._device._ip,
                                                    src=src, dst=dst)

        self._device.local_op.command_blocking(cmd)

    def upload(self, src, dst, recursive=True):
        """Upload a file on the device."""
        src, dst = Utils.escape_path_scp(src), Utils.escape_path_scp(dst)
        self._device.printer.debug("Uploading: %s -> %s" % (src, dst))

        cmd = 'sshpass -p "{password}" scp {hostverification} -P {port}'.format(password=self._device._password,
                                                                                hostverification=Constants.DISABLE_HOST_VERIFICATION,
                                                                                port=self._device._port)
        if recursive: cmd += ' -r'
        cmd += ' {src} {username}@{ip}:{dst}'.format(src=src,
                                                    username=self._device._username,
                                                    ip=self._device._ip,
                                                    dst=dst)

        self._device.local_op.command_blocking(cmd)

    # ==================================================================================================================
    # FILE SPECIFIC
    # ==================================================================================================================
    def build_temp_path_for_file(self, fname):
        """Given a filename, returns the full path for the filename in the device's temp folder."""
        return os.path.join(self._device.TEMP_FOLDER, Utils.extract_filename_from_path(fname))

    def create_timestamp_file(self, fname):
        """Create a file with the current time of last modification, to be used as a reference."""
        ts = self.build_temp_path_for_file(fname)
        cmd = 'touch %s' % ts
        self.command_blocking(cmd)
        return ts

    def chmod_x(self, fname):
        """Chmod +x the provided path."""
        cmd = 'chmod +x %s' % fname
        self.command_blocking(cmd)

    def parse_plist(self, plist, convert=True, sanitize=False):
        """Given a plist file, copy it to temp folder, convert it to XML, and run plutil on it."""
        def sanitize_plist(plist):
            self._device.printer.debug('Sanitizing content from: {}'.format(plist_copy))
            remote_temp = self.build_temp_path_for_file('sanitize_temp')
            cmd = "tr < {} -d '\\000' > {}".format(plist_copy, remote_temp)
            self.command_blocking(cmd, internal=True)
            cmd = "tr < {} -d '\\014' > {}".format(remote_temp, plist_copy)
            self.command_blocking(cmd, internal=True)
            cmd = "tr < {} -d '\\015' > {}".format(plist_copy, remote_temp)
            self.command_blocking(cmd, internal=True)
            self.file_copy(remote_temp, plist_copy)

        # Copy the plist
        plist_temp = self.build_temp_path_for_file(plist.strip("'"))
        plist_copy = Utils.escape_path(plist_temp)
        self._device.printer.debug('Copy the plist to temp: {}'.format(plist_copy))
        self.file_copy(plist, plist_copy)
        # Convert to xml
        if convert:
            self._device.printer.debug('Converting plist to XML: {}'.format(plist_copy))
            cmd = '{plutil} -convert xml1 {plist}'.format(plutil=self._device.DEVICE_TOOLS['PLUTIL'], plist=plist_copy)
            self.command_blocking(cmd, internal=True)
        # Get the content
        self._device.printer.debug('Extracting content from: {}'.format(plist_copy))
        # Sanitize (possible to have NULL bytes)
        if sanitize:
            sanitize_plist(plist_copy)
        # Cat the content
        cmd = 'cat {}'.format(plist_copy)
        out = self.command_blocking(cmd, internal=True)
        content = str(''.join(out).encode('utf-8'))
        # Parse it with plistlib
        self._device.printer.debug('Parsing plist content')
        pl = plistlib.readPlistFromString(content)
        return pl

    def read_file(self, fname, grep_args=None):
        """Given a filename, prints its content on screen."""
        cmd = 'cat {fname}'.format(fname=fname)
        if grep_args:
            cmd += ' | grep {grep_args}'.format(grep_args=grep_args)
        return self.command_blocking(cmd, internal=True)

    def write_file(self, fname, body):
        """Given a filename, write body into it"""
        cmd = "echo \"{content}\" > {dst}".format(content=body, dst=fname)
        self.command_blocking(cmd)
