from __future__ import print_function
import select
import socket
import asyncore

from ..utils.constants import Constants
from ..utils.utils import Retry


# ======================================================================================================================
# ASYNC CLIENT
# ======================================================================================================================
class AsyncClient(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host, port))
        self.buffer = ''
        self.read = False

    def readable(self):
        return True

    def writable(self):
        return (len(self.buffer) > 0)

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self, marker=Constants.AGENT_OUTPUT_END):
        """Read output from socket."""
        self.setblocking(True)
        data = ""
        while True:
            ready = select.select([self], [], [], Constants.AGENT_TIMEOUT_READ)
            if ready[0]:
                temp = self.recv(8192)
                if marker in temp:
                    data += temp[:temp.find(marker)]
                    break
                data += temp
        self.setblocking(False)
        return data

    def handle_write(self, cmd):
        """Write command to socket."""
        self.buffer = cmd
        sent = self.send(self.buffer + '\r\n')
        self.buffer = self.buffer[sent:]


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
        self._device.printer.verbose("{} Disconnecting from agent...".format(Constants.AGENT_TAG))

    @Retry()
    def exec_command_agent(self, cmd):
        self._device.printer.debug("{} Executing command: {}".format(Constants.AGENT_TAG, cmd))
        self.client.handle_write(cmd)
        return self.read_result()

    def read_result(self):
        self._device.printer.debug("{} Parsing result (are you sure the agent is in the foreground?)".format(Constants.AGENT_TAG))
        return self.client.handle_read()
