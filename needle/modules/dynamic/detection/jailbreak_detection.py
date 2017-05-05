from core.framework.module import BaseModule
import ast
import time
import difflib


class Module(BaseModule):
    meta = {
        'name': 'Jailbreak Detection',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Verify that the app cannot be run on a jailbroken device. Currently detects if the app applies jailbreak detection at startup.',
        'options': (
        ),
        'comments': [
             'Make sure that the device is unlocked before you run this module',
        ]
    }
    PID = None
    WATCH_TIME = 10
    EXIT = False

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def _monitor_fs_start(self):
        # Remote output file
        self.fsmon_out = self.device.remote_op.build_temp_path_for_file("reportcrash")
        # Run command in a thread
        cmd = '{app} -j -a {watchtime} -P "ReportCrash" {flt} &> {fname} & echo $!'.format(app=self.device.DEVICE_TOOLS['FSMON'],
                                                                                           watchtime=self.WATCH_TIME,
                                                                                           flt='/',
                                                                                           fname=self.fsmon_out)
        self.device.remote_op.command_background_start(self, cmd)

    def _parse_changed_files(self):
        # Read output of file monitoring
        file_list_str = self.device.remote_op.read_file(self.fsmon_out)
        if not file_list_str:
            self.printer.warning('No crashes identified. It is possible that jailbreak detection might be applied at a later stage in the app.')
            self.EXIT = True
            return
        # Intepret string to list
        file_list = ast.literal_eval(file_list_str[0])
        # Eliminate duplicates and filter log files
        fnames = list(set([el['filename'] for el in file_list]))
        self.crashes = filter(lambda x: x.endswith('.log'), fnames)
        # Print identified files
        if self.crashes:
            self.printer.notify('The following crash files has been identified')
            map(self.printer.notify, self.crashes)
            self.EXIT = False
        else:
            self.printer.warning('No crashes identified. It is possible that jailbreak detection might be applied at a later stage in the app.')
            self.EXIT = True

    # ==================================================================================================================
    # CRASHES
    # ==================================================================================================================
    def detect_crash_files(self):
        # Monitor filesystem for a crash
        self.printer.info("Monitoring the filesystem for a crash...")
        self._monitor_fs_start()
        # Launch the app
        self.printer.info("Launching the app multiple times to trigger a crash...")
        self.device.app.open(self.APP_METADATA['bundle_id'])
        self.device.app.open(self.APP_METADATA['bundle_id'])
        self.device.app.open(self.APP_METADATA['bundle_id'])
        time.sleep(self.WATCH_TIME)
        # Parse changed files
        self.printer.info("Looking for crash files...")
        self._parse_changed_files()

    def parse_crash_files(self):
        self.printer.info("Parsing current status of crash files...")
        self.crash_details = []
        for fp in self.crashes:
            content = self.device.remote_op.read_file(fp)
            self.crash_details.append({'file': fp, 'content': content})

    def diff_crash_files(self):
        arxan = False
        for el in self.crash_details:
            # Prepare orig and new
            fname, content_orig = el['file'], el['content']
            self.printer.info('Analyzing: %s' % fname)
            content_new = self.device.remote_op.read_file(fname)
            # Diff
            diff = difflib.unified_diff(content_orig, content_new)
            # Extract new lines
            crashes = []
            if diff:
                self.printer.notify('New crashes identified (probable indicator of jailbreak detection):')
                for dd in diff:
                    dline = dd.strip()
                    if dline.startswith('+') and not dline.endswith('+'):
                        self.printer.notify(dline)
                        crashes.append(dline)
                        if 'KERN_INVALID_ADDRESS' in dline:
                            arxan = True
            self.add_issue('Jailbreak Detection (crash identified)', crashes[0], 'INVESTIGATE', None)
        if arxan:
            self.printer.notify('Arxan Detected!')
            self.add_issue('Jailbreak Detection (vendor identified)', 'Arxan Detected', 'HIGH', None)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Detect crash files
        self.detect_crash_files()

        if not self.EXIT:
            # Parse crash files
            self.parse_crash_files()
            # Launch the app
            self.printer.info("Launching the app again...")
            self.device.app.open(self.APP_METADATA['bundle_id'])
            self.device.app.open(self.APP_METADATA['bundle_id'])
            self.device.app.open(self.APP_METADATA['bundle_id'])
            # Diff crash files
            self.diff_crash_files()
