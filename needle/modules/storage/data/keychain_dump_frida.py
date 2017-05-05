from core.framework.module import FridaScript
import json

class Module(FridaScript):
    meta = {
        'name': 'Frida Script: Keychain Dumper',
        'author': 'Bernard Wagner (@MWRLabs)',
        'description': 'Retrieve all the keychain items belonging to the target application',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
if (ObjC.available) {

    function StringFromNSStringUTF8(nsstring){
      var bytearray = nsstring.dataUsingEncoding_(4);
      return Memory.readUtf8String(bytearray.bytes(),bytearray.length());
    }

    var SecAccessControlGetConstraints = new NativeFunction(ptr(Module.findExportByName("Security","SecAccessControlGetConstraints")),'pointer',['pointer']);

    function decodeACL(entry){
        var finalDecodedValue = "";
        if (entry.containsKey_("accc")){
          var accessControls = ObjC.Object(SecAccessControlGetConstraints(entry.objectForKey_("accc")));
          if (accessControls.handle != 0x00){
            var accessControlEnumerator = accessControls.keyEnumerator();
            var accessControlItemKey;
            var finalUserPresence = "";
            while ((accessControlItemKey = accessControlEnumerator.nextObject()) !== null) {
              var accessControlItem = accessControls.objectForKey_(accessControlItemKey);

              switch (StringFromNSStringUTF8(accessControlItemKey)) {
                  case "dacl":
                    return "Default ACL";
                  case "osgn":
                    finalDecodedValue += "PrivateKeyUsage "
                  case "od":
                      var constraints = accessControlItem;
                      var constraitEnumerator = constraints.keyEnumerator();
                      var constraintItemKey;
                      while ((constraintItemKey = constraitEnumerator.nextObject()) !== null){
                          switch (StringFromNSStringUTF8(constraintItemKey)) {
                            case "cpo":
                              finalDecodedValue += " UserPresence "
                              break;
                            case "cup":
                              finalDecodedValue += " DevicePasscode "
                              break;
                            case "pkofn":
                              finalDecodedValue += (constraints.objectForKey_("pkofn") == 1 ? " Or " : " And ")
                              break;
                            case "cbio":
                              finalDecodedValue += ((constraints.objectForKey_("cbio").count()) == 1 ? " TouchIDAny " : " TouchIDCurrentSet ")
                              break;
                            default:
                              break;
                          }
                      }
                      break;
                  case "prp":
                    finalDecodedValue += "ApplicationPassword"
                    break;
                  default:
                    break;
                }
            }
        }
      }
      return finalDecodedValue;
  }

  var constants = {
    "ck":"kSecAttrAccessibleAfterFirstUnlock",
    "ak":"kSecAttrAccessibleWhenUnlocked",
    "cku":"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    "dk":"kSecAttrAccessibleAlways",
    "dku":"kSecAttrAccessibleAlwaysThisDeviceOnly",
    "akpu":"kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
    "aku":"kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    "ck":"kSecAttrAccessibleAfterFirstUnlock",
    "cku":"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
    "dk":"kSecAttrAccessibleAlways",
    "akpu":"kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
    "ak":"kSecAttrAccessibleWhenUnlocked",
    "aku":"kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    "dku":"kSecAttrAccessibleAlwaysThisDeviceOnly",
    "cert":"kSecClassCertificate",
    "class":"kSecClass",
    "genp":"kSecClassGenericPassword",
    "idnt":"kSecClassIdentity",
    "inet":"kSecClassInternetPassword",
    "keys":"kSecClassKey",
  }

  var SecItemCopyMatching = new NativeFunction(ptr(Module.findExportByName("Security","SecItemCopyMatching")),'pointer',['pointer','pointer']);
  var NSJSONSerialization = ObjC.classes.NSJSONSerialization;

  var query = ObjC.classes.NSMutableDictionary.dictionary();
  query.addObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true),"r_Attributes");
  query.addObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true),"r_Ref");
  query.addObject_forKey_(ObjC.classes.__NSCFBoolean.numberWithBool_(true),"r_Data");
  query.addObject_forKey_("m_LimitAll","m_Limit");

  var secItemClasses = ["genp", "inet", "cert", "keys", "idnt"];
  var secItemClass;

  for (secItemClassIter in secItemClasses) {
    query.setObject_forKey_(secItemClasses[secItemClassIter],"class");
    var resultPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(resultPtr, NULL);
    if (SecItemCopyMatching(query, resultPtr) == 0) {
        var result = new ObjC.Object(Memory.readPointer(resultPtr));
        for (var i = 0; i < result.count(); i++){
            var entry = result.objectAtIndex_(i);
            send(JSON.stringify({
                Data: ObjC.classes.NSString.stringWithUTF8String_(entry.objectForKey_("v_Data").bytes()).valueOf(),
                EntitlementGroup: entry.objectForKey_("agrp").valueOf(),
                Protection: constants[entry.objectForKey_("pdmn")].valueOf(),
                AccessControls: decodeACL(entry),
                CreationTime: entry.objectForKey_("cdat").valueOf(),
                Account: entry.objectForKey_("acct").valueOf(),
                Service: entry.objectForKey_("svce").valueOf(),
                ModifiedTime: entry.objectForKey_("mdat").valueOf(),
                kSecClass: constants[secItemClasses[secItemClassIter]]
            }));
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_script_dump_keychain.txt", self)

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
        self.printer.info("Keychain Items:")
        self.print_cmd_output()
        self.add_issue('Keychain items detected ({})'.format(len(self.results)), None, 'INVESTIGATE', self.options['output'])

