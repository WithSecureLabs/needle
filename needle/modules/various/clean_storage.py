from core.framework.module import BaseModule
from core.utils.constants import Constants


class Module(BaseModule):
    meta = {
        'name': 'Clean Storage',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Clean device storage from leftovers of other tools (e.g., Frida)",
        'options': (
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def clean_frida(self):
        self.printer.info("Cleaning Frida cache...")
        self.device.remote_op.dir_delete(Constants.DEVICE_PATH_FRIDA_CACHE, force=True)
        self.device.remote_op.command_blocking("killall frida-server")

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.clean_frida()
