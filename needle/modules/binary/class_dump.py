from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Class Dump',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Dump the class interfaces',
        'options': (
            ('dump_interfaces', False, True, 'Set to True to dump each interface in its own file'),
            ('output', "", False, 'Full path of the output file, or to the folder where to save the interfaces'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_temp_path_for_file(self, "classdump")

    def _class_dump(self):
        if self.options['dump_interfaces']:
            # Dump interfaces
            self.printer.info("Dumping interfaces...")
            folder = self.device.remote_op.build_temp_path_for_file("interfaces")
            cmd = '{bin} -H -o {folder} "{appbin}" 2>/dev/null'.format(bin=self.device.DEVICE_TOOLS['CLASS-DUMP'],
                                                           folder=folder,
                                                           appbin=self.fname_binary)
            out = self.device.remote_op.command_blocking(cmd)
            folder_out = self.options['output'] if self.options['output'] else self.local_op.build_temp_path_for_file("interfaces")
            # Leftovers Cleanup
            if self.local_op.file_exist(folder_out): self.local_op.file_delete(folder_out)
            if self.local_op.dir_exist(folder_out): self.local_op.dir_delete(folder_out)
            self.local_op.dir_create(folder_out)
            # Download interfaces
            self.printer.info("Retrieving interfaces...")
            self.device.remote_op.download(folder, folder_out, recursive=True)
            self.printer.notify("Interfaces saved in: %s" % folder_out)
        else:
            # Dump classes
            self.printer.info("Dumping classes...")
            cmd = '{bin} "{appbin}" 2>/dev/null'.format(bin=self.device.DEVICE_TOOLS['CLASS-DUMP'], appbin=self.fname_binary)
            out = self.device.remote_op.command_blocking(cmd)
            # Save to file
            outfile = self.options['output'] if self.options['output'] else None
            # Print to console
            self.printer.notify("The following content has been dumped: ")
            self.print_cmd_output(out, outfile)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Decrypt the binary and unzip the IPA
        self.fname_binary = self.device.app.decrypt(self.APP_METADATA)

        # CLASS DUMP
        self._class_dump()
