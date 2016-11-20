from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Launcher',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Run Frida scripts (JS payloads)',
        'options': (
            ('payload', "", True, 'Full path of the JS payload file'),
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        FridaScript.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("frida_launcher.txt", self)
        self.output = []

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Parse the payload
        payload = self.options['payload']
        self.printer.info("Parsing payload: %s" % payload)
        hook = open(payload, "r")
        script = self.session.create_script(hook.read())

        # Load the payload
        script.on('message', self.on_message)
        script.load()
        self.printer.notify("Payload loaded. You can continue to use the app now...")

        # Save to file
        self.print_cmd_output(self.output, self.options['output'], silent=True)
