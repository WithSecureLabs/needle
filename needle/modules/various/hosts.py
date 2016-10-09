from core.framework.module import BaseModule
from core.utils.constants import Constants


class Module(BaseModule):
    meta = {
        'name': 'Hosts File',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Show the content of the device's /etc/hosts file, and offer the chance to edit it",
        'options': (
            ('edit', False, True, 'Modify the /etc/hosts file of the device.'),
            ('program', 'VIM', True, 'Select the program to use for editing the file. Currently supported: VIM, NANO'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Define paths
        self.path_remote = Constants.DEVICE_PATH_HOSTS
        self.path_local  = self.local_op.build_temp_path_for_file(self, "hosts")

        # Read hosts file
        self.printer.info("Looking for the hosts file...")
        if not self.device.remote_op.file_exist(self.path_remote):
            raise Exception("Hosts file not found on device!")
        content = self.device.remote_op.read_file(self.path_remote)
        self.printer.notify('Content of /etc/hosts:')
        self.print_cmd_output(content, None)

        # Modify the file
        if self.options['edit']:

            # Check that the user entered a recognised editor in the PROGRAM option by seeing if it
            # exists in the TOOLS_LOCAL directory
            if self.options['program'] in self.TOOLS_LOCAL:
                editor = self.TOOLS_LOCAL[self.options['program']]
            else:
                self.printer.error('Editing program "{}" specified is not supported.'.format(self.options['program']))
                return

            # Pull the file
            self.device.pull(self.path_remote, self.path_local)

            # Modify it in the selected editor
            cmd = '{editor} {fname}'.format(editor=editor,
                                         fname=self.path_local)
            self.local_op.command_interactive(cmd)

            # Backup
            self.printer.debug("Backing up the original hosts file...")
            bkp = "{}.bkp".format(self.path_remote)
            self.device.remote_op.file_copy(self.path_remote, bkp)

            # Updating device
            self.printer.info("Uploading new hosts file to device...")
            self.device.push(self.path_local, self.path_remote)
