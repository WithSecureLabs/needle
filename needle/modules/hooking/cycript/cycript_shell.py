from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Cycript Shell',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Spawn a Cycript shell attached to the target app',
        'options': (
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Launch the app
        self.printer.info("Launching the app...")
        self.device.app.open(self.APP_METADATA['bundle_id'])
        # Search for PID
        binaryPath = self.APP_METADATA['binary_path'].replace("/private","")
        binaryPath = binaryPath.replace("'","")
        pid = self.device.app.search_pid(binaryPath)
        # Launch Cycript shell
        self.printer.info("Spawning a Cycript shell...")
        cmd = "{bin} -p {app}".format(bin=self.device.DEVICE_TOOLS['CYCRIPT'], app=pid)
        self.device.remote_op.command_interactive_tty(cmd)
