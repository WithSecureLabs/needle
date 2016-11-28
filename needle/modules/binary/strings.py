from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Strings',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Find strings in the (decrypted) application binary, then try to extract URIs and ViewControllers',
        'options': (
            ('length', 10, True, 'Minimum length for a string to be considered'),
            ('filter', '', False, 'Filter the output (grep)'),
            ('output', True, False, 'Full path of the output file'),
            ('analyze', True, False, 'Analyze recovered strings and try to recover URI'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("strings", self)

    def analyze_strings(self, str_list):
        self.printer.info('Analyzing strings (press any key to continue)...')
        test_cases = [
            {'name': 'HTTP_URI', 'test': 'http://'},
            {'name': 'HTTPS_URI', 'test': 'https://'},
            {'name': 'ViewControllers', 'test': 'ViewController'},
        ]
        for tc in test_cases:
            filtered = list(set(filter(lambda x: tc['test'] in x, str_list)))
            if filtered:
                # Save to file
                outfile = '%s_%s' % (self.options['output'], tc['name']) if self.options['output'] else None
                self.printer.notify(tc['name'])
                self.print_cmd_output(filtered, outfile)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Decrypt the binary and unzip the IPA
        self.fname_binary = self.device.app.decrypt(self.APP_METADATA)

        # Extract strings
        self.printer.verbose("Analyzing binary...")
        if self.options['filter']:
            query = str(self.options['filter']).strip('''"''''')
        else:
            query = ''
        cmd = '''{bin} "{app}" | awk 'length > {length}' | sort -u | grep -E '{query}' '''.format(bin=self.device.DEVICE_TOOLS['STRINGS'],
                                                                                                  app=self.fname_binary,
                                                                                                  length=self.options['length'],
                                                                                                  query=query)
        out = self.device.remote_op.command_blocking(cmd)
        if out:
            # Save to file
            outfile = self.options['output'] if self.options['output'] else None
            # Print to console
            self.printer.notify("The following strings have been found: ")
            self.print_cmd_output(out, outfile)
            # Analysis
            if self.options['analyze']:
                self.analyze_strings(out)
        else:
            self.printer.info("No meaningful strings found")
