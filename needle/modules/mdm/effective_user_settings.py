from core.framework.module import BaseModule
from core.framework.framework import FrameworkException
from core.utils.utils import Utils
from core.utils.constants import Constants


class Module(BaseModule):
    meta = {
        'name': 'MDM Effective User Settings',
        'author': 'Oliver Simonnet (@MWRLabs)',
        'description':  'Extract and compare the configuration '\
                        'of the device against a supplied configuration file, and present a '\
                        'summary of any conflicts found between the two configurations along '\
                        'with recommended changes.',
        'options': (
            ('template', "", False, 'Configuration template. [Plist]'),
            ('output', True, True,  'Full path of the output folder.'),
            ('pull_only', True, False, 'Only save the configuration file')
        ),
        'comments': [
            'TEMPLATE: an EffectiveUserSettings.plist file specifying the desired configuration.',
            'PULL_ONLY: pull the configuration from the device and store it locally. Used if you only wish to obtain a '\
            'copy of the configuration file and not perform an assessment']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    def save_file(self, remote_name, local_name):
        """Pulls a file from the device and returns the local file name."""
        if not self.options['output']:
            return
        temp_name = 'MDM_{}'.format(local_name)
        local_name = self.local_op.build_output_path_for_file(temp_name, self)
        self.device.pull(remote_name, local_name)
        return local_name

    def structure_data(self, config_file):
        """Parse Plist configuration data into dict."""
        try:
            config, merged = Utils.plist_read_from_file(config_file), {}
            for k in config.keys(): 
                merged.update(config[k])
            return merged
        except:
            self.printer.error('Invalid file: %s' % config_file)
            raise FrameworkException('Invalid configuration file!')

    def compare(self, f_current, f_desired):
        """Compare two config files."""
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
                        status = '[DISABLED]'

                # Check for Config and Desired config setting mismatch
                if v != current[k]:
                    alert_tracker += 1
                    attribute = k +': '
                    if status != '':
                        attribute += status

                    self.printer.warning('[WEAK] %s' % attribute)

                    # If attribute consists of multiple dict values, process and output
                    if Utils.is_plist(current[k]) and len(current[k]) > 1:
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
                            self.printer.notify('%s%s' % (attribute, recommendation))

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
        self.printer.info('Searching for Configuration file...')

        # Check if the EffectiveUserSettings.plist file is present
        config_file = Constants.DEVICE_PATH_EFFECTIVE_USER_SETTINGS_IOS10 if "10" in self.device._ios_version else Constants.DEVICE_PATH_EFFECTIVE_USER_SETTINGS_IOS9_AND_BELOW
        if not self.device.remote_op.file_exist(config_file):
            raise FrameworkException('Could not find: %s' % config_file)

        # Pull Effective User Settings plist
        local_name = Utils.extract_filename_from_path(config_file)
        local_file = self.save_file(config_file, local_name)

        if not self.options['pull_only']:
            # Comparing configuration with template
            self.printer.info('Assessing Configuration...')
            if not self.options['template']:
                raise FrameworkException('Template not provided')
            self.compare(local_file, self.options['template'])

        self.printer.notify('Configuration Saved to: %s' % local_file)
