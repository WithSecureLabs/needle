from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Title',
        'author': '@AUTHOR (@TWITTER)',
        'description': 'Description',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    // Actual payload
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
        self.options['output'] = self.local_op.build_output_path_for_file(self, "template.txt")
        # Output array (do not delete)
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
