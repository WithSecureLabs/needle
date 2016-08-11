from core.framework.module import BaseModule
from core.utils.constants import Constants
from core.utils.menu import choose_from_list
import time


class Module(BaseModule):
    meta = {
        'name': '>>>>>>>>>>>>>TODO',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': '>>>>>>>>>>>>>TODO',
        'options': (
            ('fuzz_list', "", False, 'Full path of the file containing the fuzz list'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        self.options['fuzz_list'] = Constants.IPC_FUZZ_LIST

    def _open_uri(self, uri):
        cmd = '''{bin} {uri}'''.format(bin=self.device.DEVICE_TOOLS['UIOPEN'], uri=uri)
        self.device.remote_op.command_blocking(cmd)

    def fuzz(self, test):
        # Build string
        uri = '''%s://%s''' % (self.ipc, test.strip())
        self.printer.info("Fuzzing: %s" % uri)
        # Open URI
        self._open_uri(uri)
        time.sleep(3)
        # Kill process
        self.printer.verbose("Killing app now...")
        self.device.remote_op.kill_proc(self.APP_METADATA['binary_name'])
        time.sleep(3)
        # Check crash
        #TODO



    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Retrieve apps' URI handlers
        self.printer.info("Retrieving URI handlers...")
        handlers = self.APP_METADATA['url_handlers']
        if handlers:
            self.printer.notify('{:<20}'.format('URL Handlers',))
            self.ipc = choose_from_list(handlers)
        else:
            self.printer.error('URL Handlers not found')
            return

        # Load fuzz list
        self.printer.info("Loading fuzz list...")
        fuzz_file = self.options['fuzz_list']
        fuzz_list = open(fuzz_file, 'r').readlines()

        # Fuzz
        map(self.fuzz, fuzz_list)
















'''




@crash_report_folder = "/var/mobile/Library/Logs/CrashReporter"
def crashed?
crashes = $device.ops.dir_glob @crash_report_folder, "*"
crashed = false
crashes.each { |x|
if x.include? $selected_app.binary_name
crashed = true
end
}
crashed
end














'''