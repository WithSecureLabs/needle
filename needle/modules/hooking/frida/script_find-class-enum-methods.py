from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Script: find class and enumerate its methods',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Find the target class specified and enumerate its methods',
        'options': (
            ('output', True, False, 'Full path of the output file'),
            ('target_class', "", True, 'Target class, whose methods needs to be enumerated.'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    for(var className in ObjC.classes) {
        if(ObjC.classes.hasOwnProperty(className)) {
            if(className == "%s") {
                console.log("Found target class : " + className);
                console.log("Methods found : ")
                var methods = ObjC.classes.%s.$methods
                for (var i = 0; i < methods.length; i++) {
                    send(methods[i]);
                }
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_script_enummethods.txt", self)
        self.output = []

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Build the payload string
        target_class = self.options['target_class']
        payload = self.JS % (target_class, target_class)

        # Run the payload
        try:
            self.printer.info("Parsing payload")
            hook = payload
            script = self.session.create_script(hook)
            script.on('message', self.on_message)
            script.load()
        except Exception as e:
            self.printer.warning("Script terminated abruptly")

        # Save to file
        self.print_cmd_output(self.output, self.options['output'], silent=True)
