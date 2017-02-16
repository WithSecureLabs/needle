from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Application Container',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Print and clone the Bundle and Data folder of the application',
        'options': (
            ('download', False, True, 'Clone the Bundle and Data folder locally'),
            ('silent', False, True, 'Silent mode. Will not print folder structure to screen'),
            ('output', True, False, 'Full path of the output folder')
        ),
    }

    tree = '''\
     -print 2>/dev/null | awk '!/\.$/ { \
        for (i=1; i<NF; i++) { \
            printf("%4s", "|") \
        } \
        print "-- "$NF \
    }' FS='/'
            '''

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']

    def _print_structure(self, directory):
        cmd = "{bin} {dir_str}".format(bin=self.device.DEVICE_TOOLS['FIND'], dir_str=directory['path'])
        cmd = cmd + self.tree
        out = self.device.remote_op.command_blocking(cmd)
        self.device.printer.notify("Content of the {} folder:".format(directory['name']))
        self.print_cmd_output(out)

    def _download_folder(self, directory):
        self.device.printer.info("Retrieving the content of the {} folder. This might take a while...".format(directory['name']))
        outname = self.device.local_op.build_output_path_for_file('Containers_%s' % directory['name'], self)
        self.device.remote_op.download(directory['path'], outname, recursive=True)
        self.device.printer.notify("The content of the {} folder has been cloned locally: {}".format(directory['name'], outname))

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # App Container
        dirs = [
            {'name': 'BUNDLE', 'path': self.APP_METADATA['bundle_directory']},
            {'name': 'DATA', 'path': self.APP_METADATA['data_directory']},
        ]

        # Print content
        if not self.options['silent']:
            map(self._print_structure, dirs)

        # Clone the folders
        if self.options['download']:
            map(self._download_folder, dirs)
