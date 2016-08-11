from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Test Module',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Description',
        'options': (
            ('name', False, True, 'description'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Any other customization goes here

        # Setting default output file
        #self.options['output'] = self.local_op.build_temp_path_for_file(self, "strings.txt")


    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):

        pass
        '''

        cmd = "{bin} {app} | awk 'length > {length}' | sort -u".format(bin=self.device.DEVICE_TOOLS['STRINGS'],
                                                                       app=self.APP_METADATA['binary_path'],
                                                                       length=self.options['length'])
        out = self.device.remote_op.command_blocking(cmd)
        # Save to file
        outfile = self.options['output'] if self.options['output'] else None
        # Print to console
        self.printer.notify("The following strings has been found: ")
        self.print_cmd_output(out, outfile)


        # Decrypt the binary and unzip the IPA
        self.fname_binary = self.device.app.decrypt(self.APP_METADATA)

        # Print cmd out to screen
        self.device.remote_op.command_blocking(cmd, internal=False)
        self.device.remote_op.command_interactive_tty(cmd)


        # INTERACTIVE: interactive shell, other python script
        self.local_op.command_interactive(cmd)


        # Launch the app
        self.printer.info("Launching the app...")
        self.device.app.open(self.APP_METADATA['bundle_id'])


        # BACKGROUND
        # Output file
        fname = self.device.remote_op.build_temp_path_for_file("pbwatcher")
        # Run command in a thread
        cmd = '{app} {sleep} &> {fname} & echo $!'.format(app=self.device.DEVICE_TOOLS['PBWATCHER'],
                                                          sleep=self.options['sleep'],
                                                          fname=fname)
        self.device.remote_op.command_background_start(self, cmd)




        # Pull file
        fname = Utils.extract_filename_from_path(option)
        temp_file = self.local_op.build_temp_path_for_file(self, fname)
        self.device.pull(option, temp_file)


######################################################

        out = self._device.remote_op.command_blocking(cmd, internal=True)

        # new logging class
        self.printer.debug/verbose/info/notify/warning/error()


        ################################################################################################################
        # METADATA
        metadata = {
            'uuid': uuid,
            'name': name,
            'app_version': app_version,
            'bundle_id': bundle_id,
            'bundle_directory': bundle_directory,
            'data_directory': data_directory,
            'binary_directory': binary_directory,
            'binary_path': binary_path,
            'binary_name': binary_name,
            'entitlements': entitlements,
            'platform_version': platform_version,
            'sdk_version': sdk_version,
            'minimum_os': minimum_os,
            'url_handlers': url_handlers,
            'architectures': architectures,
        }
        uuid = self.APP_METADATA['uuid']

        # DEVICE CONSTANTS
        self.device.TEMP_FOLDER
        self.device.PATH_TOOLS['DUMPDECRYPTED']
        PATH_TOOLS = {
            'CYCRIPT': 'cycript',
            'CLASS-DUMP-Z': 'class-dump-z',
            'DUMPDECRYPTED': '/usr/lib/dumpdecrypted.dylib',
            'FIND': 'find',
            'FRIDA': 'frida',
            'KEYCHAINEDITOR': '/var/root/keychaineditor',
            'LIPO': 'lipo',
            'OPEN': '/usr/bin/open',
            'OTOOL': 'otool',
            'STRINGS': 'strings',
        }

        # LOCAL TOOLS
        PATH_LOCAL_TOOLS = {
            'SQLITE3': 'sqlite3',
            'BINARYCOOKIEREADER': '', # updated on __init__
        }
        self.PATH_LOCAL_TOOLS['SQLITE3']

        # Launch the app
        self.print_verbose("Launching the app...")
        App.open_app(self.device, self.APP_METADATA['bundle_id'])

        # Create a file with the current time of last modification
        self.print_verbose("Creating timestamp file...")
        fname = 'timestamp-caching-snapshot'
        self.device.create_timestamp_file(fname)

        # Pretty print output
        self.print_pretty_cmd_output(out)

        # Verbosity levels
        self.print_debug('DEBUG')
        self.print_verbose('VERBOSE')
        self.print_output('STANDARD')
        self.print_alert('SUCCESS')
        self.print_exception('EXCEPTION')
        self.print_error('ERROR')
        self.print_alert('{:<20}: {:<30}'.format('Name', self.APP_METADATA['name']))

        # Command is going to be printed automatically if VERBOSE
        out = self.exec_command('ls')

        # Execute single command via full SSH shell
        self.device.exec_command_tty(cmd)

        # Local temp file
        fname = os.path.basename(option)
        temp_file = self.get_local_path(fname)
        self.delete_local_file(fname)

        # Save to file - 1
        temp_file = self.get_local_path(fname)
        self.save_to_file(txt, temp_file)

        # Save to file - 2
        def __init__(self, params):
            BaseModule.__init__(self, params)
            self.options['output'] = self.get_local_path("keychain-dump.txt")
        # ('output', False, False, 'Full path to the output file')
        if self.options['output']:
            self.save_to_file(out, self.options['output'])

        # Run local command
        app = self.PATH_LOCAL_TOOLS['SQLITE3']
        cmd = 'python {app} {temp_file}'.format(app=app, temp_file=temp_file)
        self.exec_local_command(cmd)


        App.detect_architectures(self.device, binary)
        '''
