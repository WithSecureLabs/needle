from core.framework.module import BaseModule
from core.framework.framework import FrameworkException
from core.device.device import Device
from core.utils.utils import Utils
from core.utils.constants import Constants
import re, sys, plistlib

class Module(BaseModule):
    meta = {
        'name': 'MDM Assess',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description': 'Automated MDM Configuration Assessment tool.',
        'options': (
            ('template', True, True, 'Configuration template.[Plist]'),
            ('mode', False, True, 'Output mode [1|2|3].')
        ),
        'comments': [
            'MODE: 1 Displays misconfigurations only.',
            'MODE: 2 Displays recomendations.',
            'MODE: 3 Displats all configutaion.',
            'TEMPLATE: This is an EffectiveUserSettings.plist file containing you desired configuration.']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['mode'] = 1

    # Constructs ouput filename
    def set_output_name(self, remote_file):
        file_name = Utils.extract_filename_from_path(remote_file)
        file_name = 'mdm_assess_{}'.format(file_name)
        return self.local_op.build_output_path_for_file(file_name, self)

    # Check if file is a valid Plist
    def is_plist(self, config_file):
        try: 
            plistlib.readPlist(config_file)
            return True
        except: 
            # If incorrect format, print error and exit
            self.printer.error("Invalid configuration file!")
            self.printer.debug("Invalid file: %s" % config_file)
            raise FrameworkException()
        
    # Parse Plist configuration data into dict
    def parse_config_data(self, config_file):
        if self.is_plist(config_file):
            config, merged = plistlib.readPlist(config_file), {}
            for k in config.keys(): merged.update(config[k])
            return merged

    # Compare two config files
    def compare(self, f_config, f_desired):
        config  = self.parse_config_data(f_config)
        desired = self.parse_config_data(f_desired)
        misConfigs = 0

        # Print output header
        print; self.printer.info(40*'-')
        self.printer.notify("MDM Configuration Assessment")
        self.printer.info(40*'-')

        # Compare attributes
        for k,v in desired.items():
            if k in config.keys():
                # Get setting status
                status = ""
                if len(v) != 0 and len(v) <= 1:
                    status = "ENABLED" if str(config[k][config[k].keys()[0]]) == "True" else "DISSABLED"
                # Check for Config and Desired config setting mismatch
                if v != config[k]:
                    message = k +( ": "+status if status != "" and self.options['mode'] >= 2 else "")
                    self.printer.warning("[BAD ] %s" % message)
                    misConfigs += 1

                    # Print mismatch details if in mode 2
                    if self.options['mode'] >= 2:
                        # If attribute consists of multiple dict values process and print
                        if type(config[k]) is plistlib._InternalDict and len(config[k]) > 1:
                            for k1,v1 in config[k].items():
                                message = "\t" + str(k1) + ": " + str(v1)
                                recomendation = ""

                                if config[k][k1] != desired[k][k1]:
                                    recomendation = " (Recommend: %s)" % str(desired[k][k1])
                                # Print config status and recommended value
                                self.printer.info(message + recomendation)
                        # Else print config status and recomended value
                        else:
                            val = desired[k]
                            recommend = "ENABLED" if str(val[val.keys()[0]]) == "True" else "DISSABLED"
                            self.printer.info("\tRecommend: %s" % recommend)
                    else: pass
                else:
                    if self.options['mode'] >= 3:
                        # Print non-misconfigured attributes if in mode 3
                        self.printer.notify("[GOOD] %s: %s" % (k,status))

        # Print output footer
        self.printer.info(40*'-')
        self.printer.notify("%s/%s Misconfigurations" % (misConfigs, len(desired)))
        self.printer.info(40*'-');print

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.verbose("Searching for Configuration file...")

        # Check EffectiveUserSettings.plist file is present!
        arg = Constants.DEVICE_PATH_EFFECTIVE_CONFIG
        cmd = '{bin} {arg}'.format(bin=self.device.DEVICE_TOOLS['FIND'], arg=arg)
        config = self.device.remote_op.command_blocking(cmd)[0].strip()

        if not config:
            self.printer.error("No Configuration files found!")
            self.printer.debug("Could not find %s" % arg)
            return

        # Pull Effective User Settings plist
        outFile = self.set_output_name(arg)
        self.device.pull(config, outFile)

        # Comaparing configuration with template
        self.printer.verbose("Comparing Configuration...")
        self.compare(outFile, self.options['template'])