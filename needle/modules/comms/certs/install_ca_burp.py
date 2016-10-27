from core.framework.module import BaseModule
from core.utils.constants import Constants


class Module(BaseModule):
    meta = {
        'name': 'Install Burp Proxy CA Certificate',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Install the CA Certificate of Burp on the device.',
        'options': (
            ('port', 9090, True, 'Proxy service port.'),
            ('burp_ip', False, True, 'Burp proxy server IP.'),
            ('burp_port', False, True, 'Burp proxy server PORT.'),
        ),
        'comments': ['Connect this workstation and the device to the same Wi-Fi',
                     'Configure the device to use this host as proxy',
        ]
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['burp_ip'] = self.local_op.get_ip()
        self.options['burp_port'] = 8080

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Parse variables
        port = self.options['port']

        # Run mitmdump in the background
        self.printer.notify('Configure the device to use this host as proxy: {ip}:{port}'.format(ip=self.local_op.get_ip(), port=port))
        self.printer.info('Press return when ready...')
        raw_input()
        self.printer.verbose('Running MitmProxy in the background')
        cmd = "{proxyapp} -p {port} --upstream http://{burp_ip}:{burp_port} > /dev/null".format(
            proxyapp=self.TOOLS_LOCAL['MITMDUMP'],
            port=port,
            burp_ip=self.options['burp_ip'],
            burp_port=self.options['burp_port'])
        self.local_op.command_background_start(cmd)

        # Prompt to install CA on device
        self.printer.notify('Installing CA Certificate on device, please follow the instructions on screen.')
        cmd = '{uiopen} {caurl}'.format(uiopen=self.device.DEVICE_TOOLS['UIOPEN'],
                                        caurl=Constants.CA_BURP_URL)
        self.device.remote_op.command_blocking(cmd)
        self.printer.info('Press return when ready...')
        raw_input()

        # Stopping mitmdump
        self.local_op.command_background_stop('mitmdump')
