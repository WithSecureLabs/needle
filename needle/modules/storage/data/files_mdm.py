from core.framework.module import BaseModule
from core.device.device import Device
from core.utils.menu import choose_from_list_data_protection, choose_from_list, choose_yes_no
from core.utils.utils import Utils
from core.utils.printer import Colors

class Module(BaseModule):
    meta = {
        'name': 'MDM dump',
        'author': 'Oliver Simonnet (@mwrlabs)',
        'description': 'Locate and dump MDM configuration files',
        'options': (
            ('bulk', False, False, 'Dump all configuration files in a selected directory.'),
            ('autosave', False, False, 'Automatically save files. (No save prompt)'),
            ('output', True, True, 'File output directory.')
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file(self, "mdm")

    # Prompt user to select a directory, and return directory string
    def select_dir(self, directories):
        option = choose_from_list(directories)
        if option is 'All': dirs_str =  ' '.join(directories[:-1]) 
        else: dirs_str = option

        self.printer.info("Selecting files from: [%s%s%s]" % (Colors.B, dirs_str.replace(" ", "\n\t"), Colors.N))
        return dirs_str

    # Compose cmd string, and return cmd output
    def get_files(self, dir_str):
        cmd = '{bin} {dirs_str} -type f -name "*.plist"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dir_str)
        out = self.device.remote_op.command_blocking(cmd)
        retrieved_files = out

        return retrieved_files

    # Filter out duplicate directories, and return list
    def filter_dirs(self, dirs):
        directories = []; 
        [directories.append(Utils.get_file_path(x)) for x in dirs if Utils.get_file_path(x) not in directories]
        if not self.options['bulk']: directories.append('All')

        return directories

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Looking for MDM Configuration file locations...")

        # Find MDM config file locations
        cmd = '{bin} / -type f -name "MDM*.plist" -o -name "UserSettings.plist"'.format(bin=self.device.DEVICE_TOOLS['FIND'])
        out = self.device.remote_op.command_blocking(cmd)

        if not out:
            self.printer.info("No Configuration files found")
            return

        directories = self.filter_dirs(out)

        if not self.options['bulk']:
            self.individ_mode(directories)
        else:
            self.printer.warning("Running in bulk mode!")
            self.bulk_mode(directories)

    # Run standard mode
    def individ_mode(self, directories):
        dirs_str = self.select_dir(directories)
        retrieved_files = self.get_files(dirs_str)

        # Begin "individual file" user interactivity loop
        while True and not self.options['bulk']:
            option = choose_from_list(retrieved_files) 

            # Run plutil on selected file
            self.printer.info("Dumping content of the file...")
            pl = dict(self.device.remote_op.parse_plist(option))

            # Initialize output filename
            outfile = ""
            if self.options['output']:
                fileName = Utils.extract_filename_from_path(option.strip())
                outfile = str(self.options['output']+"/"+fileName.replace('.', '_export.'))
            else: 
                outfile = None

            # Print Data to user
            self.print_cmd_output(pl)

            if self.options['autosave']:
                self.device.pull(option.strip(), outfile)
            else:
                save = choose_yes_no("Would you like to %spull%s ths file?" % (Colors.R, Colors.N))
                if save: self.device.pull(option.strip(), outfile)
                    
            # Ask user if they wish to view another file
            yes = choose_yes_no("Would you like to inspect another file?")
            if not yes: break

    # Run bulk gather mode
    def bulk_mode(self, directories):
        while True:
            dirs_str = self.select_dir(directories)
            retrieved_files = self.get_files(dirs_str)

            for i in range(len(retrieved_files)):
                f = retrieved_files[i].strip()
                fileName = Utils.extract_filename_from_path(f)
                outfile = str(self.options['output']+"/"+fileName.replace('.', '_export.'))
                
                if self.options['autosave']:
                    self.device.pull(f, outfile)
                else:
                    self.printer.info("File: %s (%d/%d)" % (f, i+1, len(retrieved_files)))
                    save = choose_yes_no("Would you like to %spull%s ths file?" % (Colors.R, Colors.N))
                    if save: self.device.pull(f, outfile)

            # Ask the user if they want to dump another directory
            yes = choose_yes_no("Would you like to %sdump%s another directory?" % (Colors.R, Colors.N))
            if not yes: break
