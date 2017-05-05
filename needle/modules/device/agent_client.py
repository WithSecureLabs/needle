from core.framework.module import BaseModule
from core.utils.constants import Constants


class Module(BaseModule):
    meta = {
        'name': 'Simple Client',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Send commands to the Needle Agent on the device",
        'options': (
            ('command', "", True, 'The command to pass to the agent'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        cmd = self.options['command']
        out = self.device.agent.exec_command_agent(cmd)
        self.print_cmd_output(out)
