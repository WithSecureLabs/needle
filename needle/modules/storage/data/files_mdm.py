from core.framework.module import BaseModule
from core.device.device import Device
from core.utils.menu import choose_from_list_data_protection, choose_from_list, choose_boolean
from core.utils.utils import Utils
import re

class Module(BaseModule):
    meta = {
        'name': 'MDM Assess',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description': 'Automated MDM Configuration Assessment tool.',
        'options': (
            ('template', True, True, 'Configuration template.[Plist|plutil-output]'),
            ('verbosity', False, True, 'Output verbosity[1|2|3].'),
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
        self.options['verbosity'] = 1

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
        mismatch, bad = 0, 0

        # Print header
        print "\n"+40*"-"
        self.printer.notify("MDM Configuration Assessment")
        print 40*"-"
        
        for i in range(len(config))[:-1]:
            if mismatch > 3:
                self.printer.error("Template/config mismatch!")
                exit(1)

            if config[i].split("\n")[0] != desired[i].split("\n")[0]:
                self.printer.warning("mismatch found!")
                mismatch += 1
                continue

            if config[i] != desired[i]:
                self.printer.error("[ BAD] " + config[i].split("\n")[0])
                bad += 1

                if self.options["verbosity"] >= 2:
                    for x in config[i].split("\n")[1:]:
                        print "\b    ",
                        self.printer.verbose(x)
            else:
                if self.options["verbosity"] == 3:
                    self.printer.info( "[GOOD] " + config[i].split("\n")[0])

        # Print footer
        print 40*'-'
        self.printer.notify("{bad}/{total} Misconfigurations".format(bad=bad, total=len(desired)))
        print 40*'-'+"\n"
        
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