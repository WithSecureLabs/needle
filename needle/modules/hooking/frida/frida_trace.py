from core.framework.module import FridaModule
from core.framework.framework import FrameworkException


class Module(FridaModule):
    meta = {
        'name': 'Frida Trace',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Trace the specified functions using frida-trace',
        'options': (
            ('functions', False, False, 'Comma separated list of functions to trace (Example: send*,recv*,CCCryptorCreate*)'),
            ('methods', False, False, 'Comma separated list of Objective-C methods to trace (Example: -[NSView drawRect:])'),
            ('modules', False, False, 'Comma separated list of modules to trace (Example: libcommonCrypto*)'),
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_pre(self):
        if not self.options['functions'] and not self.options['methods'] and not self.options['modules']:
            raise FrameworkException('Value required for at least one option')
        return FridaModule.module_pre(self)

    def module_run(self):
        # Parse options
        functions = self.options['functions']
        methods = self.options['methods']
        modules = self.options['modules']

        # Build command
        cmd = '{bin} -R -f {app}'.format(bin=self.TOOLS_LOCAL['FRIDA-TRACE'],
                                         app=self.APP_METADATA['bundle_id'])

        if functions:
            fun_list = functions.split(',')
            fun_list_string = ''.join([' -i "{}"'.format(el) for el in fun_list])
            cmd += fun_list_string
        if methods:
            method_list = methods.split(',')
            method_list_string = ''.join([' -m "{}"'.format(el) for el in method_list])
            cmd += method_list_string
        if modules:
            modules_list = modules.split(',')
            modules_list_string = ''.join([' -I "{}"'.format(el) for el in modules_list])
            cmd += modules_list_string

        # Launch frida-trace
        self.printer.info("Starting frida-trace...")
        self.local_op.command_interactive(cmd)
