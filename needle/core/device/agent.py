from __future__ import print_function
import telnetlib

from ..utils.constants import Constants


# ======================================================================================================================
# TELNET CLIENT
# ======================================================================================================================
class TelnetClient(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.timeout = Constants.AGENT_TELNET_TIMEOUT
        self.CRLF = Constants.AGENT_TELNET_CRLF
        self.session = None

    def connect(self):
        try:
            self.session = telnetlib.Telnet(self.host, self.port, self.timeout)
        except:
            raise Exception("Timeout while establishing a connection with the agent. Have you started it?")

    def disconnect(self):
        if self.session:
            self.session.close()

    def read_until(self, str):
        self.session.read_until(str)

    def exec_command(self, cmd):
        self.session.write("{}{}".format(cmd, self.CRLF))

    def read_result(self):
        self.session.read_until(Constants.AGENT_OUTPUT_START)
        tn = self.session.read_until(Constants.AGENT_OUTPUT_END)
        res_clean = tn[:-len(Constants.AGENT_OUTPUT_END)]
        return res_clean


# ======================================================================================================================
# AGENT WRAPPER
# ======================================================================================================================
class NeedleAgent(object):

    def __init__(self, device):
        self._device = device
        self._ip = self._device._ip
        self._port = self._device._agent_port
        self._telnet = TelnetClient(self._ip, self._port)

    # ==================================================================================================================
    # EXPORTED COMMANDS
    # ==================================================================================================================
    def connect(self):
        self._device.printer.verbose("{} Connecting to agent ({}:{})...".format(Constants.AGENT_TAG, self._ip, self._port))
        self._telnet.connect()
        self._telnet.read_until(Constants.AGENT_WELCOME)
        self._device.printer.notify("{} Successfully connected to agent ({}:{})...".format(Constants.AGENT_TAG, self._ip, self._port))

    def disconnect(self):
        self._device.printer.verbose("{} Disconnecting from agent...".format(Constants.AGENT_TAG))
        self._telnet.disconnect()

    def exec_command_agent(self, cmd):
        self._device.printer.debug("{} Executing command: {}".format(Constants.AGENT_TAG, cmd))
        self._telnet.exec_command(cmd)
        return self.read_result()

    def read_result(self):
        self._device.printer.debug("{} Attempting to reading result".format(Constants.AGENT_TAG))
        return self._telnet.read_result()
