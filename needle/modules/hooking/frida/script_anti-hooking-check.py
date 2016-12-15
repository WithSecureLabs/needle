from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Script: Anti Hooking Checks',
        'author': 'Henry Hoggard (@MWRLabs)',
        'description': 'Display an Alert in the target application. Can be used as simple proof that there are no anti-hooking checks in place.',
        'options': (
            ('title', "Needle", True, 'Title of alert box.'),
            ('content', "If this message is visible, this application has insufficient anti-hooking protections.", True, 'Content of alert box.')
        ),
    }

    JS = '''\
if(ObjC.available) {
    var handler = new ObjC.Block({
      retType: 'void',
      argTypes: ['object'],
      implementation: function () {
      }
    });
    var UIAlertController = ObjC.classes.UIAlertController;
    var UIAlertAction = ObjC.classes.UIAlertAction;
    var UIApplication = ObjC.classes.UIApplication;
    ObjC.schedule(ObjC.mainQueue, function () {
      var title = "%s";
      var content = "%s";
      var alert = UIAlertController.alertControllerWithTitle_message_preferredStyle_(title, content, 1);
      var defaultAction = UIAlertAction.actionWithTitle_style_handler_('OK', 0, handler);
      alert.addAction_(defaultAction);
      UIApplication.sharedApplication().keyWindow().rootViewController().presentViewController_animated_completion_(alert, true, NULL);
    })
} else {
    console.log("Objective-C Runtime is not available!");
}
    '''

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        FridaScript.__init__(self, params)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Run the payload
        try:
            self.printer.info("Parsing payload")
            title = self.options['title']
            content = self.options['content']
            hook = self.JS % (title, content)
            script = self.session.create_script(hook)
            script.on('message', self.on_message)
            script.load()
        except Exception as e:
            self.printer.warning("Script terminated abruptly")
