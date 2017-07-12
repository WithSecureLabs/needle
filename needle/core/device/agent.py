from __future__ import print_function
from socket import error as socketerror
import socket

from ..utils.constants import Constants
from ..utils.utils import Retry


# ======================================================================================================================
# ASYNC CLIENT
# ======================================================================================================================
class AsyncClient():
    def __init__(self, host, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((host, port))
        except socketerror as se:
            raise se

    def close(self):
        if self.socket:
            self.socket.close()
    
    def send_to_device(self, cmd, marker=Constants.AGENT_OUTPUT_END):
        self.socket.send(cmd + '\r\n')
        data = ""
        while True:
            temp = self.socket.recv(8192)
            if temp:
                if marker in temp:
                    data += temp[:temp.find(marker)]
                    break
                data += temp
        return data    


# ======================================================================================================================
# AGENT WRAPPER
# ======================================================================================================================
class NeedleAgent(object):

    def __init__(self, device):
        self._device = device
        self._ip = self._device._ip
        self._port = self._device._agent_port
        self.client = None

    # ==================================================================================================================
    # EXPORTED COMMANDS
    # ==================================================================================================================
    def connect(self):
        self._device.printer.verbose("{} Connecting to agent ({}:{})...".format(Constants.AGENT_TAG, self._ip, self._port))
        self.client = AsyncClient(self._ip, self._port)
        self._device.printer.notify("{} Successfully connected to agent ({}:{})...".format(Constants.AGENT_TAG, self._ip, self._port))

    def disconnect(self):
        if self.client:
            self._device.printer.verbose("{} Disconnecting from agent...".format(Constants.AGENT_TAG))
            self.client.close()

    @Retry()
    def exec_command_agent(self, cmd):
        # Currently the agent needs to be in the foreground in order to being able to receive commands
        if self._device.ssh:
            self._device.app.open(Constants.AGENT_BUNDLE_ID)
        self._device.printer.debug("{} Executing command: {}".format(Constants.AGENT_TAG, cmd))
        return self.client.send_to_device(cmd)
