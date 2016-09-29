from core.framework.module import BaseModule
from core.device.device import Device
from core.utils.menu import choose_from_list_data_protection, choose_from_list, choose_yes_no
from core.utils.utils import Utils

class Module(BaseModule):
    meta = {
        'name': 'MDM dump',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description': 'Locate and dump MDM configuration files',
        'options': (
            ('dump_all', False, False, 'DUMP_ALL mode. Dump all configuration files in a selected directory'),
            ('autosave', False, False, 'Automatically save files. (Recomended with DUMP_ALL mode)'),
            ('silent', True, True, 'Silent mode. Will not print file contents to screen.'),
            ('output', True, True, 'Ful,l path of the output folder')
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']
        self.running = True

    # Prompt user to select a directory, and return directory string
    def select_dir(self, directories):
        option = choose_from_list(directories)
        self.printer.info("Selecting files from: [%s]" % option)
        return option

    # Compose cmd string, and return cmd output
    def get_files(self, dir_str):
        cmd = '{bin} {dirs_str} -maxdepth 1 -type f -name "*.plist"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dir_str)
        out = self.device.remote_op.command_blocking(cmd)
        return out

    # Filter out duplicate directories, and return list
    def filter_dirs(self, dirs):
        directories = list(set([Utils.extract_directory_from_path(x) for x in dirs if "needle" not in x]))
        return directories

    def set_output_name(self, remote_file):
        fileName = Utils.extract_filename_from_path(remote_file)
        fileName = 'mdm_export_{}'.format(fileName)
        return self.local_op.build_output_path_for_file(self, fileName)

    def save_file(self, remote_file, local_file):
        if self.options['autosave']:
            self.device.pull(remote_file, local_file)
        else:
            save = choose_yes_no("Would you like to pull ths file?")
            if save: self.device.pull(remote_file, local_file)

     # Run standard mode
    def individual_mode(self, directories):
        dirs_str = self.select_dir(directories)
        retrieved_files = self.get_files(dirs_str)

        # Begin "individualual file" user interactivity loop
        while self.running:
            option = choose_from_list(retrieved_files) 

            # Run plutil on selected file
            self.printer.info("Dumping content of the file...")
            pl = dict(self.device.remote_op.parse_plist(option))

            # Initialize output filename
            outFile = self.set_output_name(option.strip())

            # Print Data to user and save file
            if not self.options['silent']: self.print_cmd_output(pl)
            self.save_file(option.strip(), outFile)
                    
            # Ask user if they wish to view another file
            yes = choose_yes_no("Would you like to inspect another file?")
            if not yes: self.running = False

    # Run dump mode
    def dump_mode(self, directories):
        while self.running:
            dirs_str = self.select_dir(directories)
            retrieved_files = self.get_files(dirs_str)

            for i in range(len(retrieved_files)):
                f = retrieved_files[i].strip()
                # Initialize output
                outFile = self.set_output_name(f)

                # filename and save file
                self.printer.info("File: %s (%d/%d)" % (f, i+1, len(retrieved_files)))
                self.save_file(f, outFile)

            # Ask the user if they want to dump another directory
            yes = choose_yes_no("Would you like to dump another directory?")
            if not yes: self.running = False

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.running = True
        self.printer.info("Looking for MDM Configuration file locations...")

        if self.options['dump_all'] and not self.options['autosave']:
            self.printer.warning("Autosave recomended in DUMO_ALL mode!")

        # Find MDM config file locations
        cmd = '{bin} / -type f -name "MDM*.plist" -o -name "UserSettings.plist"'.format(bin=self.device.DEVICE_TOOLS['FIND'])
        out = self.device.remote_op.command_blocking(cmd)

        if not out:
            self.printer.error("No Configuration files found")
            return

        directories = self.filter_dirs(out)

        if not self.options['dump_all']:
            self.individual_mode(directories)
        else:
            self.printer.info("Running in dump mode!")
            self.dump_mode(directories)
