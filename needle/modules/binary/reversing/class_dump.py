from core.framework.module import BaseModule
import os


class Module(BaseModule):
    meta = {
        'name': 'Class Dump',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Dump the class interfaces',
        'options': (
            ('dump_interfaces', False, True, 'Set to True to dump each interface in its own file'),
            ('output', True, False, 'Full path of the output file, or to the folder where to save the interfaces'),
        ),
        'comments': ['This might not work on 64bit binaries. In such cases, "cycript" or "binary/reversing/class_dump_frida_enum-all-methods" are recommended',
                     ]
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("classdump", self)

    def class_dump(self):
        if self.options['dump_interfaces']:
            # Leftovers cleanup
            self.printer.debug("Leftovers cleanup...")
            folder_remote = self.device.remote_op.build_temp_path_for_file("interfaces")
            folder_local = self.options['output'] if self.options['output'] \
                                                  else self.local_op.build_output_path_for_file("interfaces", self)
            self.device.remote_op.dir_reset(folder_remote)
            self.local_op.dir_reset(folder_local)

            # Dump interfaces
            self.printer.info("Dumping interfaces...")
            cmd = '{bin} -H -o {folder} "{appbin}" 2>/dev/null'.format(bin=self.device.DEVICE_TOOLS['CLASS-DUMP'],
                                                                       folder=folder_remote,
                                                                       appbin=self.fname_binary)
            self.device.remote_op.command_blocking(cmd)

            # Download interfaces
            self.printer.info("Retrieving interfaces...")
            self.device.remote_op.download(folder_remote, folder_local, recursive=True)
            self.printer.notify("Interfaces saved in: %s" % folder_local)
        else:
            # Dump classes
            self.printer.info("Dumping classes...")
            cmd = '{bin} "{appbin}" 2>/dev/null'.format(bin=self.device.DEVICE_TOOLS['CLASS-DUMP'], appbin=self.fname_binary)
            out = self.device.remote_op.command_blocking(cmd)
            # Save to file
            outfile = self.options['output'] if self.options['output'] else None
            # Print to console
            if out:
                self.printer.notify("The following content has been dumped: ")
                self.print_cmd_output(out, outfile)
            else:
                self.printer.warning("It was not possible to dump interfaces.")
                self.printer.warning("This might happen if this is 64bit binary. In such case, 'cycript' or 'hooking/frida/script_enum-all-methods' are recommended")

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Decrypt the binary and unzip the IPA
        self.fname_binary = self.device.app.decrypt(self.APP_METADATA)
        # Perform class dump
        self.class_dump()
