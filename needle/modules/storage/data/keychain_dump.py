from core.framework.module import BaseModule
from core.utils.menu import choose_from_list
from core.utils.utils import Utils

class Module(BaseModule):
    meta = {
        'name': 'Keychain Dump',
        'author': '@LanciniMarco (@MWRLabs) (modifications by @tghosth (@JoshCGrossman))',
        'description': 'Dump the keychain to plist files and store these files in the output directory. '
        'The user also has the option to analyze one of the files with or without a filter.',
        'options': (
            ('filter', '', False, 'Filter to apply when analyzing. '
             'If empty, the entire keychain file will be shown'),
            ('output', True, True, 'Full path of the output folder'),
            ('analyze', False, True, 'Prompt to pick one file to analyze'),
        ),
        'comments': [
            'Ensure the screen is unlocked before dumping the keychain']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file(self, "keychain")
        # Setting default filter
        if self.APP_METADATA:
            self.printer.info('Setting filter to: %s (you can change it in options)' % self.APP_METADATA['binary_name'])
            self.options['filter'] = self.APP_METADATA['binary_name']

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    def save_file(self, remote_name, local_name, silent):
        """Save it locally"""
        self.printer.debug("Dumping content of the file: {}".format(remote_name))

        # Pull the file locally
        outfile = '{}_{}.txt'.format(self.options['output'], str(local_name))
        self.device.pull(remote_name, outfile)

        # Not silent means that this file should be analyzed
        if not silent:

            # Apply a filter if specified
            grep_args = None
            if self.options['filter']:
                grep_args = ' -i -a "{}" -C 10 '.format(self.options['filter'])

            # Display the file (with filter if necessary) to screen
            self.print_cmd_output(self.local_op.cat_file(outfile, grep_args))


    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):

        # Composing the command string
        cmd = '{}'.format(self.device.DEVICE_TOOLS['KEYCHAIN_DUMP'])
        msg = "Dumping the keychain"

        # Dump Keychain (outputs .plist files)
        self.printer.info(msg)
        self.device.remote_op.command_blocking(cmd)

        # Get a list of all files in the current directory (which should include the 4 keychain dump files)
        all_files = self.device.remote_op.dir_list('.')

        # list to store the keychain dump files which were found.
        keychain_files = []

        # Ascertain which keychain dump files were actually created
        for filename in all_files:
            clean_name = Utils.escape_path(filename)

            if clean_name in ['cert.plist', 'genp.plist', 'inet.plist', 'keys.plist']:
                keychain_files.append(clean_name)

        # If no dump files could be found, return an error
        if len(keychain_files) == 0:
            self.printer.warning('No content found. Ensure the screen is unlocked before dumping the keychain')
            return

        # If analyzing then allow the user to choose a file to analyze, otherwise just show the list.
        self.printer.info("The following keychain dump files have been found:")

        chosen_file = ''
        if self.options['analyze']:
            # Show Menu
            chosen_file = choose_from_list(keychain_files)
        else:
            choose_from_list(keychain_files, choose=False)

        # Pull all files to the output folder specified on the local machine
        self.printer.notify('Saving all keychain dump files...')
        for fname in keychain_files:
            # Save the file locally
            self.save_file(fname, fname, fname != chosen_file)

            # clean up the dumped keychain files on the device
            self.device.remote_op.file_delete(fname)
