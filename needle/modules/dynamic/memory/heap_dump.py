from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Heap Dump',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Dump memory regions of the app and look for strings',
        'options': (
            ('filter', "", True, 'String to look for in the dumped memory'),
            ('output', True, False, 'Full path of the output file')
        ),
        'comments': [
            'Make sure that the device is unlocked before you run this module',
            'Based on the process outlined in heapdump-ios: https://github.com/NetSPI/heapdump-ios',
        ]
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("heap_dump.txt", self)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Launch the app
        self.printer.info("Launching the app...")
        self.device.app.open(self.APP_METADATA['bundle_id'])
        pid = self.device.app.search_pid(self.APP_METADATA['name'])

        # Create temp files/folders
        dir_dumps = self.device.remote_op.build_temp_path_for_file("gdb_dumps")
        fname_mach = self.device.remote_op.build_temp_path_for_file("gdb_mach")
        fname_ranges = self.device.remote_op.build_temp_path_for_file("gdb_ranges")
        self.device.remote_op.write_file(fname_mach, "info mach-regions")
        if self.device.remote_op.dir_exist(dir_dumps): self.device.remote_op.dir_delete(dir_dumps)
        self.device.remote_op.dir_create(dir_dumps)

        # Enumerate Mach Regions
        self.printer.info("Enumerating mach regions...")
        cmd = '''\
        gdb --pid="%s" --batch --command=%s 2>/dev/null | grep sub-regions | awk '{print $3,$5}' | while read range; do
        echo "mach-regions: $range"
        cmd="dump binary memory %s/dump`echo $range| awk '{print $1}'`.dmp $range"
        echo "$cmd" >> %s
        done ''' % (pid, fname_mach, dir_dumps, fname_ranges)
        self.device.remote_op.command_blocking(cmd)

        # Dump memory
        self.printer.info("Dumping memory (it might take a while)...")
        cmd = 'gdb --pid="%s" --batch --command=%s &>>/dev/null' % (pid, fname_ranges)
        self.device.remote_op.command_blocking(cmd)

        # Check if we have dumps
        self.printer.verbose("Checking if we have dumps...")
        file_list = self.device.remote_op.dir_list(dir_dumps, recursive=True)
        failure = filter(lambda x: 'total 0' in x, file_list)
        if failure:
            self.printer.error('It was not possible to attach to the process (known issue in iOS9. A Fix is coming soon)')
            return

        # Extract strings
        self.printer.info("Extracting strings...")
        cmd = 'strings {}/* 2>/dev/null | grep -i "{}"'.format(dir_dumps, self.options['filter'])
        strings = self.device.remote_op.command_blocking(cmd)

        if strings:
            self.print_cmd_output(strings, self.options['output'])
        else:
            self.printer.warning("No strings found. The app might employ anti-debugging techniques.")
