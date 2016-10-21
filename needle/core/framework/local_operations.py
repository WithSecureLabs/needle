import os
import pty
import time
import shutil
import datetime
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

    def dir_copy(self, src, dst):
        src = Utils.escape_path(src)
        dst = Utils.escape_path(dst)
        shutil.copytree(src, dst)

    def dir_is_empty(self, path):
        return not os.listdir(path)

    def dir_reset(self, path):
        if os.path.isfile(path):
            "Actually this is a file, not a directory"
            if self.file_exist(path): self.file_delete(path)
            self.dir_create(path)
        else:
            "It is already a directory"
            if not self.dir_exist(path):
                # Folder does not exist, create it
                self.printer.debug("Creating folder: {}".format(path))
                self.dir_create(path)
            elif not self.dir_is_empty(path):
                # Folder exist, and is not empty
                self.printer.warning("Attention! The folder chosen to store the output is not empty: {}".format(path))
                self.printer.warning("Do you want to erase its content first?")
                self.printer.warning("Y: the content will be deleted")
                self.printer.warning("N: no action will be taken (destination files might be overwritten in case of filename clash)")
                choice = raw_input("[y/n]: ").strip()
                if choice.lower() == 'y':
                    self.dir_delete(path)
                    self.dir_create(path)

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
    def build_output_path_for_file(self, module, fname):
        """Given a filename, returns the full path in the local output folder."""
        return os.path.join(module._global_options['output_folder'], Utils.extract_filename_from_path(fname))

    def build_temp_path_for_file(self, module, fname):
        """Given a filename, returns the full path in the local temp folder."""
        return os.path.join(module.path_home_temp, Utils.extract_filename_from_path(fname))

    def delete_temp_file(self, module, fname):
        """Given a filename, delete the corresponding file in the local temp folder."""
        temp_file = self.build_temp_path_for_file(module, fname)
        self.file_delete(temp_file)

    def cat_file(self, fname, grep_args=None):
        """Given a filename, prints its content on screen."""
        cmd = '{bin} {fname}'.format(bin=Constants.PATH_TOOLS_LOCAL['CAT'], fname=fname)
        if grep_args:
            cmd += ' | grep {grep_args}'.format(grep_args=grep_args)
        out, err = self.command_blocking(cmd)
        self.printer.notify("Content of file '%s': " % fname)
        print(out)

    def write_file(self, fname, body):
        """Given a filename, write body into it."""
        self.printer.debug("Writing to file: {}".format(fname))
        with open(fname, "w") as fp:
            fp.write(body)

    def output_folder_setup(self, module):
        """Setup local output folder: create it if it doesn't exist. Oterhwise prompt the user and ask to back it up."""
        output = module._global_options['output_folder']
        if not os.path.exists(output):
            # Folder does not exist, create it
            self.printer.debug("Creating local output folder: {}".format(output))
            os.makedirs(output)
        elif os.listdir(output):
            # Folder exist, and is not empty
            self.printer.warning("Attention! The folder chosen to store local output is not empty: {}".format(output))
            self.printer.warning("Do you want to back it up first?")
            self.printer.warning("Y: the content will be archived in a different location, then the folder will be emptied")
            self.printer.warning("N: no action will be taken (destination files might be overwritten in case of filename clash)")
            choice = raw_input("[y/n]: ").strip()
            if choice.lower() == 'y':
                self.output_folder_backup(module)

    def output_folder_backup(self, module):
        """Backup the local output folder"""
        folder_active = module._global_options['output_folder']
        folder_backup = os.path.join(Constants.FOLDER_BACKUP,
                                     'needle-output_{}'.format(datetime.datetime.now().strftime('%Y-%m-%d-%H:%M:%S')))
        self.printer.verbose("Archiving local output folder: {active} --> {backup}".format(active=folder_active,
                                                                                           backup=folder_backup))
        self.printer.debug("Copying: {} -> {}".format(folder_active, folder_backup))
        self.dir_copy(folder_active, folder_backup)
        self.printer.debug("Deleting: {}".format(folder_active))
        self.dir_delete(folder_active)
        self.printer.debug("Recreating: {}".format(folder_active))
        self.dir_create(folder_active)

    # ==================================================================================================================
    # NETWORK
    # ==================================================================================================================
    def get_ip(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 53))
            IP = s.getsockname()[0]
        except:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP
