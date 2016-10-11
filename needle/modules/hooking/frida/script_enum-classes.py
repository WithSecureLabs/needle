from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Script: enumerate classes',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Enumerate available classes',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    for(var className in ObjC.classes) {
        if(ObjC.classes.hasOwnProperty(className)) {
            send(className);
        }
    }
} else {
    console.log("Objective-C Runtime is not available!");
}
    '''

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        FridaScript.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file(self, "frida_script_enumclasses.txt")
        self.output = []

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Run the payload
        try:
            self.printer.info("Parsing payload")
            hook = self.JS
            script = self.session.create_script(hook)
            script.on('message', self.on_message)
            script.load()
        except Exception as e:
            self.printer.warning("Script terminated abruptly")

        # Save to file
        self.print_cmd_output(self.output, self.options['output'], silent=True)
