from core.framework.module import FridaModule


class Module(FridaModule):
    meta = {
        'name': 'Frida Shell',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Spawn a Frida shell attached to the target app',
        'options': (
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Launch Frida shell
        self.printer.info("Spawning a Frida shell...")
        cmd = "{bin} -R -f {app}".format(bin=self.TOOLS_LOCAL['FRIDA'],
                                         app=self.APP_METADATA['bundle_id'])
        self.local_op.command_interactive(cmd)
