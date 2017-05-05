import re
import collections

from core.framework.module import BaseModule
from core.utils.printer import Colors


class Module(BaseModule):
    meta = {
        'name': 'Compilation Checks',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Check for protections: PIE, ARC, stack canaries, binary encryption',
        'options': (
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __run_otool(self, query, grep=None):
        """Run otool against a specific architecture."""
        cmd = '{bin} {query} {app}'.format(bin=self.device.DEVICE_TOOLS['OTOOL'],
                                              query=query,
                                              app=self.APP_METADATA['binary_path'])
        if grep: cmd = '%s | grep -Ei "%s"' % (cmd, grep)
        out = self.device.remote_op.command_blocking(cmd)
        return out

    def __check_flag(self, line, flagname, flag):
        """Extract result of the test."""
        tst = filter(lambda el: re.search(flag, el), line)
        res = True if tst and len(tst) > 0 else False
        self.tests[flagname] = res

    # ==================================================================================================================
    # CHECKS
    # ==================================================================================================================
    def _check_cryptid(self):
        out = self.__run_otool('-l', grep='cryptid')
        self.__check_flag(out, "Encrypted", "cryptid(\s)+1")

    def _check_pie(self):
        out = self.__run_otool('-hv')
        self.__check_flag(out, "PIE", "PIE")

    def _check_arc(self):
        out = self.__run_otool('-IV', grep='(\(architecture|objc_release)')
        self.__check_flag(out, "ARC", "_objc_release")

    def _check_stack_canaries(self):
        out = self.__run_otool('-IV', grep='(\(architecture|___stack_chk_(fail|guard))')
        self.__check_flag(out, "Stack Canaries", "___stack_chk_")

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.verbose("Analyzing binary...")
        for arch in self.APP_METADATA['architectures']:
            self.tests = collections.defaultdict(dict)
            # Checks
            self._check_cryptid()
            self._check_pie()
            self._check_arc()
            self._check_stack_canaries()
            # Print Output
            self.printer.notify(arch)
            for name, val in self.tests.items():
                if val:
                    self.printer.notify('\t{:>20}: {}{:<30}{}'.format(name, Colors.G, 'OK', Colors.N))
                else:
                    self.printer.error('\t{:>20}: {}{:<30}{}'.format(name, Colors.R, 'NO', Colors.N))
                    self.add_issue('Compilation check', '{}: NO'.format(name), 'HIGH', None)
