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
            ('dump_all', False, False, 'Dump all configuration files in a selected directory'),
            ('autosave', False, False, 'Automatically save files. (No save prompt)'),
            ('output', True, True, 'Full path of the output folder')
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
        if option is 'All': dirs_str =  ' '.join(directories[:-1]) 
        else: dirs_str = option
        self.printer.info("Selecting files from: [%s]" % dirs_str.replace(" ", "]\n\t\t["))
        return dirs_str

    # Compose cmd string, and return cmd output
    def get_files(self, dir_str):
        cmd = '{bin} {dirs_str} -type f -name "*.plist"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dir_str)
        out = self.device.remote_op.command_blocking(cmd)
        return out

    # Filter out duplicate directories, and return list
    def filter_dirs(self, dirs):
        directories = list(set([Utils.extract_directory_from_path(x) for x in dirs]))
        if not self.options['dump_all']: directories.append('All')
        return directories

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
            if self.options['output']:
                fileName = Utils.extract_filename_from_path(option.strip())
                fileName = 'mdm_export_{}'.format(fileName)
                outfile = self.local_op.build_output_path_for_file(self, fileName)
            else: 
                outfile = None

            # Print Data to user
            self.print_cmd_output(pl)

            if self.options['autosave']:
                self.device.pull(option.strip(), outfile)
            else:
                save = choose_yes_no("Would you like to pull ths file?")
                if save: self.device.pull(option.strip(), outfile)
                    
            # Ask user if they wish to view another file
            yes = choose_yes_no("Would you like to inspect another file?")
            if not yes: self.running = False

    # Run dump_all gather mode
    def dump_all_mode(self, directories):
        while self.running:
            dirs_str = self.select_dir(directories)
            retrieved_files = self.get_files(dirs_str)

            for i in range(len(retrieved_files)):
                f = retrieved_files[i].strip()
                fileName = Utils.extract_filename_from_path(f)
                fileName = 'mdm_export_{}'.format(fileName)
                outfile = self.local_op.build_output_path_for_file(self, fileName)
                
                if self.options['autosave']:
                    self.device.pull(f, outfile)
                else:
                    self.printer.info("File: %s (%d/%d)" % (f, i+1, len(retrieved_files)))
                    save = choose_yes_no("Would you like to pull ths file?")
                    if save: self.device.pull(f, outfile)

            # Ask the user if they want to dump another directory
            yes = choose_yes_no("Would you like to dump another directory?")
            if not yes: self.running = False

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.running = True
        self.printer.info("Looking for MDM Configuration file locations...")

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
            self.printer.info("Running in dump_all mode!")
            self.dump_all_mode(directories)
