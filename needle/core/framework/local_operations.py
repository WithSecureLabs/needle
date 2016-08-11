import os
import pty
import time
import shutil
import threading
import subprocess

from ..utils.constants import Constants
from ..utils.printer import Printer
from ..utils.utils import Utils


class LocalOperations(object):
    # ==================================================================================================================
    # INIT
    # ==================================================================================================================
    def __init__(self):
        self.printer = Printer()

    # ==================================================================================================================
    # FILES
    # ==================================================================================================================
    def file_exist(self, path):
        path = Utils.escape_path(path)
        return os.path.exists(path)

    def file_create(self, path):
        path = Utils.escape_path(path)
        if not self.file_exist(path):
            return os.mknod(path)

    def file_delete(self, path):
        path = Utils.escape_path(path)
        if self.file_exist(path):
            return os.remove(path)

    # ==================================================================================================================
    # DIRECTORIES
    # ==================================================================================================================
    def dir_exist(self, path):
        path = Utils.escape_path(path)
        return os.path.exists(path)

    def dir_create(self, path):
        path = Utils.escape_path(path)
        if not self.dir_exist(path):
            return os.makedirs(path)

    def dir_delete(self, path):
        path = Utils.escape_path(path)
        if self.dir_exist(path):
            shutil.rmtree(path)

    # ==================================================================================================================
    # COMMANDS
    # ==================================================================================================================
    def command_subproc_start(self, cmd):
        """Run a command in a subprocess and resume execution immediately."""
        self.printer.debug('[LOCAL CMD] Local Subprocess Command: %s' % cmd)
        DEVNULL = open(os.devnull, 'w')
        proc = subprocess.Popen(cmd.split(), stdout=DEVNULL, stderr=subprocess.STDOUT)
        time.sleep(2)
        return proc

    def command_subproc_stop(self, proc):
        """Stop a running subprocess."""
        self.printer.debug('[LOCAL CMD] Stopping Local Subprocess Command [pid: %s]' % proc.pid)
        proc.terminate()

    def command_blocking(self, cmd):
        """Run a blocking command: wait for its completion before resuming execution."""
        self.printer.debug('[LOCAL CMD] Local Command: %s' % cmd)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = proc.stdout.read(), proc.stderr.read()
        return stdout, stderr

    def command_interactive(self, cmd):
        """Run an interactive command: which requires an interactive shell."""
        self.printer.debug("[LOCAL CMD] Local Interactive Command: %s" % cmd)
        out = subprocess.call(cmd, shell=True)
        return out

    def command_background_start(self, cmd):
        """Run a background command: run it in a new thread and resume execution immediately."""
        self.printer.debug('[LOCAL CMD] Local Background Command: %s' % cmd)

        def daemon(cmd):
            """Daemon used to run the command so to avoid blocking the UI"""
            # Run command
            master, slave = pty.openpty()
            proc = subprocess.Popen(cmd, shell=True, stdout=slave, stderr=slave, close_fds=True)
            stdout = os.fdopen(master)
            self.printer.info("Monitoring in background...Kill this process when you want to see the dumped content")

        # Run command in a thread
        d = threading.Thread(name='daemon', target=daemon, args=(cmd,))
        d.setDaemon(True)
        d.start()
        time.sleep(2)

    def command_background_stop(self, procname):
        """Stop a running subprocess."""
        self.printer.debug('[LOCAL CMD] Stopping Local Background Command')
        cmd = 'pgrep {procname} | xargs kill -9'.format(procname=procname)
        self.command_blocking(cmd)

    # ==================================================================================================================
    # LOCAL FILES
    # ==================================================================================================================
    def build_temp_path_for_file(self, module, fname):
        """Given a filename, returns the full path in the local temp folder."""
        return os.path.join(module.path_home_temp, Utils.extract_filename_from_path(fname))

    def delete_temp_file(self, module, fname):
        """Given a filename, delete the corresponding file in the local temp folder."""
        temp_file = self.build_temp_path_for_file(module, fname)
        self.file_delete(temp_file)

    def cat_file(self, fname):
        """Given a filename, prints its content on screen."""
        cmd = '{bin} {fname}'.format(bin=Constants.PATH_TOOLS_LOCAL['CAT'], fname=fname)
        out, err = self.command_blocking(cmd)
        self.printer.notify("Content of file '%s': " % fname)
        print(out)

    # ==================================================================================================================
    # NETWORK
    # ==================================================================================================================
    def get_ip(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 0))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
