from core.framework.module import FridaScript, BaseModule


class Module(FridaScript):
    meta = {
        'name': 'Frida Script: dump UI',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Print view hierarchy',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    ObjC.schedule(ObjC.mainQueue, function() {
        const window = ObjC.classes.UIWindow.keyWindow();
        const ui = window.recursiveDescription().toString();
        send(ui);
    });
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_script_dump_ui.txt", self)

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
            self.printer.warning("Script terminated abruptly:")
            self.printer.warning(e)

    def on_message(self, message, data):
        try:
            if message:
                print("[*] {0}".format(message["payload"]))
                self.results.append(message["payload"])
        except Exception as e:
            print(message)
            print(e)