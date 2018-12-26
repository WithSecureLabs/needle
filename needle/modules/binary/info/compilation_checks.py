import re
import collections

from core.framework.module import BaseModule
from core.utils.printer import Colors


class Module(BaseModule):
    meta = {
        'name': 'Compilation Checks',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Check for protections: PIE, ARC, stack canaries, binary encryption. Check it for application binary and for local shared libraries.',
        'options': (
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __run_otool(self, query, grep=None, app=None):
        """Run otool against."""
        if not app:
            app=self.APP_METADATA['binary_path']

        cmd = '{bin} {query} {app}'.format(bin=self.device.DEVICE_TOOLS['OTOOL'],
                                              query=query,
                                              app=app)
        if grep: cmd = '%s | grep -Ei "%s"' % (cmd, grep)
        out = self.device.remote_op.command_blocking(cmd)
        return out

    def __check_flag(self, line, flagname, flag):
        """Extract result of the test."""
        tst = filter(lambda el: re.search(flag, el), line)
        res = True if tst and len(tst) > 0 else False
        self.tests[flagname] = res

    def __get_dylib_files(self):
        """
        Find all local dylib files (they start with @rpath prefix).

        retrun: dylib files set
        """
        self.printer.verbose("Getting list of dylib files...")
        cmd = '{bin} -L {app}'.format(bin=self.device.DEVICE_TOOLS['OTOOL'], app=self.APP_METADATA['binary_path'])
        out = self.device.remote_op.command_blocking(cmd)

        dylib_files = set()

        for f in out:
            f = f.strip()

            if re.search("^@rpath", f):
                local_dylib = f.replace("@rpath", self.APP_METADATA['binary_directory'] + "/Frameworks")
                dylib_path = "'{}'".format(local_dylib.split(" (compatibility version")[0])
                dylib_files.add(dylib_path)

        self.print_cmd_output("Found {} local dylib files".format(len(dylib_files)))

        return dylib_files

    # ==================================================================================================================
    # CHECKS
    # ==================================================================================================================
    def _check_cryptid(self, app=None):
        out = self.__run_otool('-l', grep='cryptid', app=app)
        self.__check_flag(out, "Encrypted", "cryptid(\s)+1")

    def _check_pie(self, app=None):
        out = self.__run_otool('-hv', app=app)
        self.__check_flag(out, "PIE", "PIE")

    def _check_arc(self, app=None):
        out = self.__run_otool('-IV', grep='(\(architecture|objc_release)', app=app)
        self.__check_flag(out, "ARC", "_objc_release")

    def _check_stack_canaries(self, app=None):
        out = self.__run_otool('-IV', grep='(\(architecture|___stack_chk_(fail|guard))', app=app)
        self.__check_flag(out, "Stack Canaries", "___stack_chk_")

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.verbose("Loading dylib files...")
        binary_files = self.__get_dylib_files()

        self.printer.verbose("Analyzing binary and dylib files...")

        binary_files.add(self.APP_METADATA['binary_path'])

        for app in binary_files:
            self.tests = collections.defaultdict(dict)
            
            # Checks
            self._check_cryptid(app)
            self._check_pie(app)
            self._check_arc(app)
            self._check_stack_canaries(app)
            
            # Print Output
            self.printer.notify(app)
            for name, val in self.tests.items():
                if val:
                    self.printer.notify('\t{:>20}: {}{:<30}{}'.format(name, Colors.G, 'OK', Colors.N))
                else:
                    self.printer.error('\t{:>20}: {}{:<30}{}'.format(name, Colors.R, 'NO', Colors.N))
                    self.add_issue('Compilation check', '{}: NO'.format(name), 'HIGH', None)

        

        # for dylib in dylib_files:
        #     self.tests = collections.defaultdict(dict)

