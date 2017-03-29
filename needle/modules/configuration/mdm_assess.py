from core.framework.module import BaseModule
from core.framework.framework import FrameworkException
from core.device.device import Device
from core.utils.utils import Utils
from core.utils.constants import Constants
from plistlib import readPlist,_InternalDict

class Module(BaseModule):
    meta = {
        'name': 'MDM Assess Effective',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description': 'Configuration Assessment Module',
        'options': (
            ('template', True, True, 'Configuration template. [Plist]'),
            ('output', True, True,  'Full path of the output folder.'),
            ('pull_only', False, False, 'Only save the configuration file')
        ),
        'comments': [
            'TEMPLATE: This is an EffectiveUserSettings.plist '\
            'file specifying the desired configuration.',
            'PULL_ONLY: Pulls the configuration from the device and '\
            'stores it locally. Used if you only wish to obtain a '\
            'copy of the configuration file and not perform an assessmen']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']


    # Pulls a file from the device and returns the local file name
    def save_file(self, remote_name, local_name):
        if not self.options['output']:
            return
        temp_name = 'MDM_Assess_Device{}'.format(local_name)
        local_name = self.local_op.build_output_path_for_file(temp_name, self)
        self.device.pull(remote_name, local_name)
        return local_name


    # Parse Plist configuration data into dict
    def structure_data(self, config_file):
        try:
            readPlist(config_file)
            config, merged = readPlist(config_file), {}
            for k in config.keys(): 
                merged.update(config[k])
            return merged
        except:
            # If not, print error and exit
            self.printer.error('Invalid configuration file!')
            self.printer.verbose('Invalid file: %s' % config_file)
            raise FrameworkException()


    # Compare two config files
    def compare(self, f_current, f_desired):
        current = self.structure_data(f_current)
        desired = self.structure_data(f_desired)
        alert_tracker = 0

        # Print output header
        print ''
        self.printer.info(40*'-')
        self.printer.notify('Device Configuration Assessment')
        self.printer.info(40*'-')

        # Compare attributes
        for k, v in desired.items():
            if k in current.keys():
                # Get setting status
                status = '[NOT CONFIGURED]' if len(v) == 0 else ''
                if len(v) == 1 and len(current[k].keys()) != 0:
                    if str(current[k][current[k].keys()[0]]) == 'True':
                        status = '[ENABLED]'
                    else:
                        status = '[DISSABLED]'

                # Check for Config and Desired config setting mismatch
                if v != current[k]:
                    alert_tracker += 1
                    attribute = k +': '
                    if status != '':
                        attribute += status

                    self.printer.warning('[WEAK] %s' % attribute)

                    # If attribute consists of multiple dict values, process and output
                    if type(current[k]) is _InternalDict and len(current[k]) > 1:
                        for k1, v1 in current[k].items():
                            attribute = '\t%s: %s' % (
                                (str(k1).replace('range', '')).ljust(9), str(v1))
                           
                            try:
                                recommendation = ''
                                if current[k][k1] != desired[k][k1]:
                                    recommendation = ' (Recommend: %s)' % str(desired[k][k1])
                            except KeyError:
                                continue

                            # Print config status and recommended value
                            self.printer.notify(attribute + recommendation)

                    # Else print config status and recommended value
                    else:
                        val = desired[k]
                        recommended = 'DISABLING'
                        if str(val[val.keys()[0]]) == 'True':
                            recommended = 'ENABLING'

                        self.printer.notify('\tRecommend: %s' % recommended)

        # Print output footer
        self.printer.info(40*'-')
        self.printer.notify('%d/%d Misconfigurations' % (alert_tracker, len(desired)))
        self.printer.info(40*'-')
        print ''


    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.verbose('Searching for Configuration file...')

        # Check EffectiveUserSettings.plist file is present!
        config_file = Constants.DEVICE_PATH_EFFECTIVE_USER_SETTINGS_IOS9_AND_BELOW
        if self.device._ios_version.split('\n')[2] >= 10:
            config_file = Constants.DEVICE_PATH_EFFECTIVE_USER_SETTINGS_IOS10

        cmd = '{bin} {arg}'.format(bin=self.device.DEVICE_TOOLS['FIND'], arg=config_file)

        try: 
            config = self.device.remote_op.command_blocking(cmd)[0].strip()
        except:
            self.printer.error('No Configuration profiles applied!')
            self.printer.Debug('Could not find %s' % config_file)
            return

        # Pull Effective User Settings plist
        local_name = Utils.extract_filename_from_path(config_file)
        local_file = self.save_file(config_file, local_name)

        if self.options['pull_only'] != True:
            # Comparing configuration with template
            self.printer.verbose('Assessing Configuration...')
            self.compare(local_file, self.options['template'])
        else:
            self.printer.notify('Configuration Saved to: %s' % local_file)