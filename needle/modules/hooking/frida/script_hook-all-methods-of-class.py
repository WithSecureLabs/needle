from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Script: hook all methods of the specified class',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Hook all the methods of the specified class',
        'options': (
            ('output', True, False, 'Full path of the output file'),
            ('target_class', "", True, 'Target class, whose methods needs to be hooked.'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    var className = "%s";
    var methods = eval('ObjC.classes.' + className + '.$methods');
    console.log("[*] Hooking methods");
    for (var i = 0; i < methods.length; i++)
    {
        var funcName = methods[i];
        var hook = eval('ObjC.classes.' + className + '["'+funcName+'"]');
        Interceptor.attach(hook.implementation, {
            onEnter: function(args) {
                console.log("[*] Detected call to: " + className.toString() + " -> " + funcName.toString());
            }
        });
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_script_hook_all_methods_of_class.txt", self)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Build the payload string
        target_class = self.options['target_class']
        payload = self.JS % (target_class,)

        # Run the payload
        try:
            self.printer.info("Parsing payload")
            hook = payload
            script = self.session.create_script(hook)
            script.on('message', self.on_message)
            script.load()
        except Exception as e:
            self.printer.warning("Script terminated abruptly")
