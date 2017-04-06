from core.framework.module import FridaScript
import json

class Module(FridaScript):
    meta = {
        'name': 'Frida Script: TLS Pinning Bypass',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Disable TLS Certificate Pinning for the target application.',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
        'comments': [
            'Based on SSL Kill Switch 2 (https://github.com/nabla-c0d3/ssl-kill-switch2) and Swizzler (https://github.com/vtky/Swizzler2)',
        ]
    }

    JS = '''\
if (ObjC.available) {
    var errSSLServerAuthCompleted = -9481;
    var kSSLSessionOptionBreakOnServerAuth = 0;
    var noErr = 0;

    var SSLHandshake = new NativeFunction(
        Module.findExportByName("Security", "SSLHandshake"),
        'int',
        ['pointer']
    );

    Interceptor.replace(SSLHandshake, new NativeCallback(function (context) {
        var result = SSLHandshake(context);
        if (result == errSSLServerAuthCompleted) {
            send("Replacing SSLHandshake");
            return SSLHandshake(context);
        }
        return result;
    }, 'int', ['pointer']));

    var SSLCreateContext = new NativeFunction(
        Module.findExportByName("Security", "SSLCreateContext"),
        'pointer',
        ['pointer', 'int', 'int']
    );

    Interceptor.replace(SSLCreateContext, new NativeCallback(function (alloc, protocolSide, connectionType) {
        send("Replacing SSLCreateContext");
        var sslContext = SSLCreateContext(alloc, protocolSide, connectionType);
        SSLSetSessionOption(sslContext, kSSLSessionOptionBreakOnServerAuth, 1);
        return sslContext;
    }, 'pointer', ['pointer', 'int', 'int']));

    var SSLSetSessionOption = new NativeFunction(
        Module.findExportByName("Security", "SSLSetSessionOption"),
        'int',
        ['pointer', 'int', 'bool']
    );

    Interceptor.replace(SSLSetSessionOption, new NativeCallback(function (context, option, value) {
        if (option == kSSLSessionOptionBreakOnServerAuth) {
            send("Replacing SSLSetSessionOption");
            return noErr;
        }
        return SSLSetSessionOption(context, option, value);
    }, 'int', ['pointer', 'int', 'bool']));

    //
    // OLD WAY
    //
    var kSecTrustResultInvalid = 0;
    var kSecTrustResultProceed = 1;
    var kSecTrustResultDeny = 3;
    var kSecTrustResultUnspecified = 4;
    var kSecTrustResultRecoverableTrustFailure = 6;
    var kSecTrustResultFatalTrustFailure = 6;
    var kSecTrustResultOtherError = 7;

    var SecTrustEvaluate = new NativeFunction(
        Module.findExportByName("Security", "SecTrustEvaluate"),
        'int',
        ['pointer', 'pointer']
    );

    Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
        send("Replacing SecTrustEvaluate");
        var ret = SecTrustEvaluate(trust, result);
        result = kSecTrustResultProceed;
        return ret;
    }, 'int', ['pointer', 'pointer']));

    //
    // COMMON FRAMEWORKS
    //
    /* AFNetworking */
    if (ObjC.classes.AFSecurityPolicy) {
        Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setSSLPinningMode:'].implementation, {
            onEnter: function (args) {
                send("Replacing AFSecurityPolicy setSSLPinningMode = 0 was " + args[2]);
                args[2] = ptr('0x0');
            }
        });
        Interceptor.attach(ObjC.classes.AFSecurityPolicy['- setAllowInvalidCertificates:'].implementation, {
            onEnter: function (args) {
                send("Replacing AFSecurityPolicy setAllowInvalidCertificates = 1 was " + args[2]);
                args[2] = ptr('0x1');
            }
        });
    }

    /* Kony */
    if (ObjC.classes.KonyUtil) {
        Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowSelfSignedCertificate'].implementation, {
            onLeave: function (retval) {
                send("Replacing KonyUtil shouldAllowSelfSignedCertificate = 1 was " + retval);
                retval.replace(0x1);
            }
        });
        Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowBundledWithSystemDefault'].implementation, {
            onLeave: function (retval) {
                send("Replacing KonyUtil shouldAllowBundledWithSystemDefault = 1 was " + retval);
                retval.replace(0x1);
            }
        });
        Interceptor.attach(ObjC.classes.KonyUtil['+ shouldAllowBundledOnly'].implementation, {
            onLeave: function (retval) {
                send("Replacing KonyUtil shouldAllowBundledOnly = 0 was " + retval);
                retval.replace(0x0);
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
        self.options['output'] = self.local_op.build_output_path_for_file("frida_pinning_bypass.txt", self)

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
