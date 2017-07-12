from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Script: hook specified method',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Hook a particular method of a specific class',
        'options': (
            ('output', True, False, 'Full path of the output file'),
            ('target_class', "", True, 'Target class'),
            ('target_method', "", True, 'Target method'),
        ),
    }

    JS = '''\
if(ObjC.available) {
    var className = "%s";
    var methodName = "%s";

    var hook = eval('ObjC.classes.' + className + '["' + methodName + '"]');
    Interceptor.attach(hook.implementation, {
          onEnter: function(args) {
                // args[0] is self
                // args[1] is selector (SEL "sendMessageWithText:")
                // args[2] holds the first function argument, an NSString
                console.log("[*] Detected call to: " + className + " -> " + funcName);
                //For viewing and manipulating arguments
                //console.log("\t[-] Value1: "+ObjC.Object(args[2]));
                //console.log("\t[-] Value2: "+(ObjC.Object(args[2])).toString());
                //console.log(args[2]);
          }
          onLeave: function(retval) {
                console.log("[*] Class Name: " + className);
                console.log("[*] Method Name: " + methodName);
                console.log("\t[-] Type of return value: " + typeof retval);
                //console.log(retval.toString());
                console.log("\t[-] Return Value: " + retval);
          }
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_script_hook_method_of_class.txt", self)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Build the payload string
        payload = self.JS % (self.options['target_class'], self.options['target_method'])

        # Run the payload
        try:
            self.printer.info("Parsing payload")
            hook = payload
            script = self.session.create_script(hook)
            script.on('message', self.on_message)
            script.load()
        except Exception as e:
            self.printer.warning("Script terminated abruptly")
            print(e)

    def module_post(self):
        pass#self.print_cmd_output()
