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
            ('output', True, True, 'Full path of the output file')
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']

    def show_image(self, sc):
        if self.options['pull']:
            self.printer.notify('Retrieving screenshots and saving them in: %s' % self.options['output'])
            for s in sc:
                # Pull file
                temp_name = Utils.extract_filename_from_path(s)
                temp_file = os.path.join(self.options['output'], temp_name)
                self.device.remote_op.download(s, temp_file)

                # Show image
                # Kali
                cmd = '{} "{}"'.format(self.TOOLS_LOCAL['EOG'], temp_file)
                out, err = self.local_op.command_blocking(cmd)
                if 'not found' in err:
                    # OS X
                    cmd = '{} "{}"'.format(self.TOOLS_LOCAL['OPEN'], temp_file)
                    self.local_op.command_blocking(cmd)

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
        self.show_image(sc)
        self.add_issue('Background Screenshot Found', sc, 'HIGH', self.options['output'])
