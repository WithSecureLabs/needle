from core.framework.module import BaseModule
from core.utils.menu import choose_from_list_data_protection
import re


class Module(BaseModule):
    meta = {
        'name': 'Grep data',
        'author': '@_fruh_',
        'description': 'Grep data in bundle and data folders. It prints out 0-80 characters before and after matched string.',
        'options': (
            ('filter', '', True, 'Filter the output (grep)'),
            ('case', False, False, 'Case sensitivity'),
            ('dataprotection', True, False, 'Check for Data Protection attributes of found files.'),
        ),
    }

    # ==================================================================================================================
    # UTILS


    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        dirs = [self.APP_METADATA['bundle_directory'], self.APP_METADATA['data_directory']]
        case = "-i" if self.options["case"] else ""

        for directory in dirs:
            self.printer.info("Looking for string '{}' in dir '{}' ...".format(self.options['filter'], directory))

            cmd = '''
            {find} "{directory}" -type f | while read fname; do 
                tmp=$(strings "$fname" | grep -oE {case} ".{{0,80}}{filter}.{{0,80}}")
                if [ $? == 0 ]; then
                    echo "File: $fname"
                    echo "$tmp"
                fi
            done'''.format(find=self.device.DEVICE_TOOLS['FIND'], directory=directory, case=case, filter=self.options['filter'])
            strings = self.device.remote_op.command_blocking(cmd)
            
            for string in strings:
                string = string.strip()

                match = re.search('^File: (.*)', string)

                if match:
                    self.printer.info("String found in:")
                    
                    if self.options["dataprotection"]:
                        data_protection = self.device.app.get_dataprotection([match.group(1)])
                        choose_from_list_data_protection(data_protection, choose=False)
                    else:
                        self.printer.info(match.group(1)[:100])
                else:
                    self.printer.notify(string)

        self.printer.info("Done")
