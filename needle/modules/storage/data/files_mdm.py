from core.framework.module import BaseModule
from core.device.device import Device
from core.utils.menu import choose_from_list_data_protection, choose_from_list, choose_boolean
from core.utils.utils import Utils
import re

class Module(BaseModule):
    meta = {
        'name': 'MDM Assess',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description': 'Assess MDM Configurateion Settings',
        'options': (
            ('template', True, True, 'Efficient configuration template.'),
            ('verbose', True, True, 'Output verbosity.'),
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

    # Format output filename
    def set_output_name(self, remote_file):
        fileName = Utils.extract_filename_from_path(remote_file)
        fileName = 'MDM_Export{}'.format(fileName)
        return self.local_op.build_output_path_for_file(self, fileName)

    # Save file
    def save_file(self, remote_file, local_file):
        if self.options['autosave']:
            self.device.pull(remote_file, local_file)
        else:
            save = choose_boolean("Would you like to pull ths file?")
            if save: self.device.pull(remote_file, local_file)

    # Check if file is Plist or a parsed Plist (plutil output) file
    def isPlist(self, configFile):
        head = self.device.remote_op.read_file(configFile)[0]
        if "<?xml" in head: return True
        elif "{\n" in head: return False

        self.printer.error("Incorrect file format!")
        exit(1)
        

    # Parse Plist configuration data into dict
    def parseConfigData(self, configFile):
        config, split, parsed = "", "", []
        plist = self.isPlist(configFile)

        if not plist:
            config = ''.join(self.device.remote_op.read_file(configFile))
        else:
            cmd = '{bin} {arg}'.format(bin=self.device.DEVICE_TOOLS['PLUTIL'], arg=configFile)
            config = ''.join(self.device.remote_op.command_blocking(cmd))

        for line in config.split('\n'):
            regex = "(^(\{|\}).*)|(^ {4}[a-zA-Z]* = .*\{.*)|(^ {4}\}\;.*)"
            if not re.compile(regex).search(line): split += line + "\n"

        config = re.compile("\};.*[ \n]").split(split)

        for element in config:
            regex = '(^ *)|(= *\{.*)|(;)'
            parsed.append('\n'.join(re.sub(regex, '', x) for x in element.split('\n')[:-1]))

        return parsed

    # Compare two config files
    def compare(self, fConfig, fDesired):
        config  = self.parseConfigData(fConfig)
        desired = self.parseConfigData(fDesired)
        missmatch = 0

        # Print header
        print "\nMDM Configuration Assessment\n"+40*"-"
        
        for i in range(len(config))[:-1]:
            if missmatch > 3:
                self.printer.error("Template/config mismatch!")
                exit(1)

            if config[i].split("\n")[0] != desired[i].split("\n")[0]:
                self.printer.warning("Missmatch found!")
                missmatch += 1
                continue

            if config[i] != desired[i]:
                self.printer.error("[ BAD] " + config[i].split("\n")[0])

                if self.options["verbose"]:
                    for x in config[i].split("\n")[1:]:
                        print "\b    ",
                        self.printer.verbose(x)
            else:
                self.printer.info( "[GOOD] " + config[i].split("\n")[0])

        # Print footer
        print 40*'-'
        
    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Find MDM config file locations
        self.printer.verbose("Searching for Configuration file...")

        arg = "/var/mobile/Library/ConfigurationProfiles/EffectiveUserSettings.plist"
        cmd = '{bin} {arg}'.format(bin=self.device.DEVICE_TOOLS['FIND'], arg=arg)
        config = self.device.remote_op.command_blocking(cmd)[0].strip()

        if not config:
            self.printer.error("No Configuration files found!")
            return
        
        # Place template config within /tmp/ directory
        template = "/tmp/" + self.options['template'].split('/')[-1]
        self.device.push(self.options["template"], template)

        # Comaparing configuration with template
        self.printer.verbose("Comparing Configuration...")
        self.compare(config, template)

        # Message of completeion
        self.printer.verbose("Complete!")



