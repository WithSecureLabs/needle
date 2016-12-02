from core.framework.module import BaseModule
from core.device.device import Device
from core.utils.menu import choose_from_list_data_protection, choose_from_list, choose_boolean
from core.utils.utils import Utils
import re, sys

class Module(BaseModule):
    meta = {
        'name': 'MDM Assess',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description': 'Automated MDM Configuration Assessment tool.',
        'options': (
            ('template', True, True, 'Configuration template.[Plist|plutil-output]'),
            ('verbosity', False, True, 'Output verbosity[1|2|3|4].')
        ),
        'comments': [
            'VERBOSITY: 1 Displays misconfigurations only.',
            'VERBOSITY: 2 Displays misconfiguration values.',
            'VERBOSITY: 3 Displays recomendations.',
            'VERBOSITY: 4 Displats all configutaion.']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['verbosity'] = 1

    # Check if file is in Plist or a plutil-output format
    def isPlist(self, configFile):
        head = self.device.remote_op.read_file(configFile)[0]
        if "<?xml" in head: return True
        elif "{\n" in head: return False

        # If incorrect format, print error and exit
        self.printer.error("Incorrect file format!")
        exit(1)
        
    # Parse Plist configuration data into dict
    def parseConfigData(self, configFile):
        config, split, parsed = "", "", []
        
        # Detemine file fromat and generate config string
        plist = self.isPlist(configFile)
        if not plist:
            config = ''.join(self.device.remote_op.read_file(configFile))
        else:
            cmd = '{bin} {arg}'.format(bin=self.device.DEVICE_TOOLS['PLUTIL'], arg=configFile)
            config = ''.join(self.device.remote_op.command_blocking(cmd))

        # Remove Unwanted data
        for line in config.split('\n'):
            regex = "(^(\{|\}).*)|(^ {4}[a-zA-Z]* = .*\{.*)|(^ {4}\}\;.*)"
            if not re.compile(regex).search(line): split += line + "\n"

        # Split config string into array of attributes
        config = re.compile("\};.*[ \n]").split(split)

        # Strip excess characters and reformat attributes
        for element in config:
            regex = '(^ *)|(= *\{.*)|(;)'
            parsed.append('\n'.join(re.sub(regex, '', x) for x in element.split('\n')[:-1]))

        return parsed

    # Compare two config files
    def compare(self, fConfig, fDesired):
        config  = self.parseConfigData(fConfig)
        desired = self.parseConfigData(fDesired)
        misConfigs = 0

        # Print output header
        print "\n"+40*"-"
        self.printer.notify("MDM Configuration Assessment")
        print 40*"-"
        
        # Compare attribute
        for i in range(len(config))[:-1]:
            # Check for termplate/config attribute mismatch
            if config[i].split("\n")[0] != desired[i].split("\n")[0]:
                self.printer.warning("Mismatch found! Invalid Template.")
                self.printet.debug("%s >> %s" % (onfig[i].split("\n")[0],desired[i].split("\n")[0]))
                exit(1)

            # Check templace compliance
            if config[i] != desired[i]:
                self.printer.error("[ BAD] " + config[i].split("\n")[0])
                misConfigs += 1

                # Print misconfiguration details Verbosely
                if self.options["verbosity"] >= 2:
                    cAttribs = config[i].split("\n")[1:]
                    dAttribs = desired[i].split("\n")[1:]
                    for i in range(len(cAttribs)):
                        print "\b    ",; self.printer.verbose(cAttribs[i])
                        if cAttribs[i] != dAttribs[i] and self.options["verbosity"] >= 3:
                            print "\b    ",; self.printer.notify(dAttribs[i]  + " [RECOMMENDED]")
            else:
                if self.options["verbosity"] == 4:
                    # Print non-isconfigured attributes
                    self.printer.info( "[GOOD] " + config[i].split("\n")[0])

        # Print output footer
        print '\b'+40*'-'
        self.printer.notify("%s/%s Misconfigurations" % (misConfigs, len(desired)))
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