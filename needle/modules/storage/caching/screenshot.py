from core.framework.module import BaseModule
from core.utils.utils import Utils
import os
import time


class Module(BaseModule):
    meta = {
        'name': 'Screenshot Caching.',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Test whether if, when the application's process is moved to the background, "
                       "sensitive information could be cached on the file system in the form of a screenshot of the application's main window",
        'options': (
            ('pull', True, True, 'Automatically pull screenshots from device'),
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Create a file with the current time of last modification
        self.printer.verbose("Creating timestamp file...")
        ts = self.device.remote_op.create_timestamp_file('timestamp-caching-snapshot')

        # Launch the app
        self.printer.info("Launching the app...")
        self.device.app.open(self.APP_METADATA['bundle_id'])

        # Ask the user to background the app
        self.printer.info("Background the app by hitting the home button, then press enter: ")
        raw_input()
        time.sleep(2)

        # Check presence of new screenshots
        self.printer.info("Checking for new screenshots...")
        folder = os.path.join(self.APP_METADATA['data_directory'], 'Library/Caches/Snapshots/')
        cmd = '{bin} {folder} -type f -newer {ts} | sort -u'.format(bin=self.device.DEVICE_TOOLS['FIND'], folder=folder, ts=ts)
        out = self.device.remote_op.command_blocking(cmd)
        if not out:
            self.printer.warning("No new screenshots were detected")
            return

        # Print to console
        self.printer.notify("Screenshots found:")
        sc = []
        for el in out:
            fname = el.strip()
            sc.append(fname)
            self.printer.notify('\t{}'.format(fname))

        # Pull files & show image
        if self.options['pull']:
            self.printer.notify('Retrieving screenshots and saving them in: %s' % self.path_home_temp)
            for s in sc:
                # Pull file
                temp_name = Utils.extract_filename_from_path(s)
                temp_file = self.local_op.build_temp_path_for_file(self, temp_name)
                self.device.remote_op.download(s, temp_file)

                # Show image
                cmd = '{} "{}"'.format(self.TOOLS_LOCAL['EOG'], temp_file)
                self.local_op.command_blocking(cmd)
