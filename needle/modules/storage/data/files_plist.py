from core.framework.module import BaseModule
from core.utils.menu import choose_from_list_data_protection
from core.utils.utils import Utils


class Module(BaseModule):
    meta = {
        'name': 'Plist Files',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'List plist files contained in the app folders, alongside with their Data Protection Class. '
                       'Plus, offers the chance to inspect them with Plutil.'
                       'Alternatively, convert and dump all of the plist files for local analysis.',
        'options': (
            ('analyze', True, True, 'Prompt to pick one file to analyze (ignored if "DUMP_ALL" is True)'),
            ('dump_all', False, True, 'Convert and save all plist files'),
            ('silent', False, False, 'Silent mode - Will not print file contents to screen when saving'),
            ('output', True, False, 'Full path and the file prefix of the output file/s')
        ),
        'comments': ['"DUMP_ALL" will build file names based on each file\'s path (changing the / symbol to the _ symbol)',
        'It will overwrite any existing files in the output directory']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file(self, "plist")

    # Convert and save the plist file locally
    def save_plist(self, fname, plist_name):
        # Run plutil
        self.printer.info("Dumping content of the file:" + fname)
        pl = self.device.remote_op.parse_plist(fname)


        # pl = dict(pl)
        plist_path = '{}_{}.txt'.format(self.options['output'], plist_name)
        outfile = plist_path if self.options['output'] else None
        self.print_cmd_output(pl, outfile, self.options['silent'])


    # Converts a full plist path to a file name, stripping the path of the bundle/data
    def convert_path_to_filename(self, fname):
        # Remove folder path from the file name to be used when saving in the output directory.
        shortname = fname.replace(self.APP_METADATA['bundle_directory'], '')
        shortname = shortname.replace(self.APP_METADATA['data_directory'], '')

        # Remove extraneous ' symbol
        shortname = shortname.replace('\'', '')

        # We want to convert the directory path to a simple filename so swap the / symbol for a _ symbol
        return shortname.replace('/', '_')

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Looking for Plist files...")

        # Compose cmd string
        dirs = [self.APP_METADATA['bundle_directory'], self.APP_METADATA['data_directory']]
        dirs_str = ' '.join(dirs)
        cmd = '{bin} {dirs_str} -type f -name "*.plist"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dirs_str)
        out = self.device.remote_op.command_blocking(cmd)

        # No files found
        if not out:
            self.printer.info("No Plist files found")
            return

        if self.options['dump_all']:
            for fname in out:
                fname = Utils.escape_path(fname.strip())

                # convert the plist path to a valid filename
                plist_name = self.convert_path_to_filename(fname)

                #convert the plist and save it locally
                self.save_plist(fname, plist_name)

        else:

            # Add data protection class
            self.printer.info("Retrieving data protection classes...")
            retrieved_files = self.device.app.get_dataprotection(out)

            # only run if dump_all is false
            if self.options['analyze']:

                # Show Menu
                self.printer.info("The following Plist files have been found:")
                option = choose_from_list_data_protection(retrieved_files)

                plist_name = Utils.extract_filename_from_path(option)

                # convert the plist and save it locally
                self.save_plist(option, plist_name)
            else:

                # Only list files, do not prompt the user
                choose_from_list_data_protection(retrieved_files, choose=False)
