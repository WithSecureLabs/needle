from core.framework.module import FridaScript
import json

class Module(FridaScript):
    meta = {
        'name': 'Frida Script: iCloud Backups',
        'author': 'Bernard Wagner (@MWRLabs)',
        'description': 'List files within Documents directory mot excluded from iCloud Backups',
        'options': (

        ),
    }

    JS = '''
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
            if (Memory.readPointer(isDirPtr) == 0){
              var resultPtr = Memory.alloc(Process.pointerSize);
              var errorPtr = Memory.alloc(Process.pointerSize);
              url.getResourceValue_forKey_error_(resultPtr,"NSURLIsExcludedFromBackupKey",errorPtr)
              var result = new ObjC.Object(Memory.readPointer(resultPtr));
              send(JSON.stringify({result:result.toString(), path:documentsPath.stringByAppendingPathComponent_(filePath).toString()}));

            }
          }
        }
        '''

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Run the payload
        try:
            self.results = []
            self.printer.info("Parsing payload")
            hook = self.JS
            script = self.session.create_script(hook)
            script.on('message', self.on_message)
            script.load()
        except Exception as e:
            self.printer.warning("Script terminated abruptly")
            print(e)

    def on_message(self, message, data):
        try:
            if message:
                self.results.append(json.loads(message["payload"]))
        except Exception as e:
            print(message)
            print(e)

    def module_post(self):
        self.printer.info("Files to be included in iCloud Backup")
        for key in self.results:
            if key["result"] == "0":
                self.printer.warning("{0}".format(key["path"]))
