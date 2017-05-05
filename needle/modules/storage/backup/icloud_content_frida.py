from core.framework.module import FridaScript
import json

class Module(FridaScript):
    meta = {
        'name': 'Frida Script: iCloud Backups',
        'author': 'Bernard Wagner (@MWRLabs)',
        'description': 'List files within the "Documents" directory not excluded from iCloud Backups',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
if (ObjC.available) {
    var NSHomeDirectory = new NativeFunction(ptr(Module.findExportByName("Foundation","NSHomeDirectory")),'pointer',[]);
    var NSFileManager = ObjC.classes.NSFileManager;
    var NSURL = ObjC.classes.NSURL;

    var documentsPath = (new ObjC.Object(NSHomeDirectory())).stringByAppendingPathComponent_("Documents");
    var enumerator = NSFileManager.defaultManager().enumeratorAtPath_(documentsPath);
    var filePath = null;

    var isDirPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(isDirPtr,NULL);

    while ((filePath = enumerator.nextObject()) != null){
        NSFileManager.defaultManager().fileExistsAtPath_isDirectory_(documentsPath.stringByAppendingPathComponent_(filePath),isDirPtr);
        var url = NSURL.fileURLWithPath_(documentsPath.stringByAppendingPathComponent_(filePath));
        if (Memory.readPointer(isDirPtr) == 0) {
            var resultPtr = Memory.alloc(Process.pointerSize);
            var errorPtr = Memory.alloc(Process.pointerSize);
            url.getResourceValue_forKey_error_(resultPtr,"NSURLIsExcludedFromBackupKey",errorPtr)
            var result = new ObjC.Object(Memory.readPointer(resultPtr));
            send(JSON.stringify({result:result.toString(), path:documentsPath.stringByAppendingPathComponent_(filePath).toString()}));
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_script_documents_backup.txt", self)

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
        self.printer.info("Files to be included in iCloud Backup:")
        self.results = [key["path"] for key in self.results if key["result"] == "0"]
        self.print_cmd_output()
        # Add issues
        self.add_issue('Files included into the iCloud Backup', self.results, 'MEDIUM', self.options['output'])
