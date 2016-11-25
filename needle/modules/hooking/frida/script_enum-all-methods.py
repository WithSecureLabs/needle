from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Script: enumerate all methods',
        'author': '@HenryHoggard (@MWRLabs)',
        'description': 'Enumerate all methods from all classes in the application',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    for(var className in ObjC.classes) {
        if(ObjC.classes.hasOwnProperty(className)) {
            send("Class: " + className);
            var methods = eval('ObjC.classes.'+className+'.$methods');
            for (var i = 0; i < methods.length; i++) {
                send(methods[i]);
            }
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_script_allmethods.txt", self)
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
            print(e)

        # Save to file
        self.print_cmd_output(self.output, self.options['output'], silent=True)
