from core.framework.module import BaseModule
from core.utils.menu import choose_from_list_data_protection


class Module(BaseModule):
    meta = {
        'name': 'CouchBase Files',
        'author': '@_fruh_',
        'description': 'List CouchBase files contained in the app folders, alongside with their Data Protection Class. ',
        'options': (
        ),
    }

    # ==================================================================================================================
    # UTILS


    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Looking for CouchBase files...")

        # Compose cmd string
        dirs = [self.APP_METADATA['bundle_directory'], self.APP_METADATA['data_directory']]
        dirs_str = ' '.join(dirs)
        cmd = '{bin} {dirs_str} -type f -name "*.cblite*"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dirs_str)
        out = self.device.remote_op.command_blocking(cmd)

        # No files found
        if not out:
            self.printer.error("No CouchBase files found")
            return

        # Save list
        self.add_issue('CouchBase files detected', out, 'INVESTIGATE', None)

        # Add data protection class
        self.printer.info("Retrieving data protection classes...")
        retrieved_files = self.device.app.get_dataprotection(out)

        # Analysis
        self.printer.info("The following CouchBase files have been found:")

        choose_from_list_data_protection(retrieved_files, choose=False)
