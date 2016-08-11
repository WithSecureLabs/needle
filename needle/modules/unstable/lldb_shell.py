from core.framework.module import DebugModule
from core.utils.constants import Constants


class Module(DebugModule):
    meta = {
        'name': 'LLDB Shell',
        'author': 'Henry Hoggard (@MWRLabs)',
        'description': 'Start an LLDB Session to debug an application.',
        'options': (
            ('exploit_dev', False, False, 'Exploit Dev Mode: Uses "lisa" scripts to make exploit development easier.'),
            ('chisel', False, False, 'Adds Facebook\'s scripts for debugging iOS applications'),
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Spawning a LLDB session...")
        cmd = "{bin} localhost:{port} {app}".format(bin=self.device.DEVICE_TOOLS['DEBUGSERVER'],
                                                    port=Constants.DEBUG_PORT,
                                                    app=self.APP_METADATA['binary_path'])
        self.device.remote_op.command_interactive_tty(cmd)
