from core.framework.module import FridaScript


class Module(FridaScript):
    meta = {
        'name': 'Frida Jailbreak Detection Bypass',
        'author': 'Henry Hoggard',
        'description': 'Hooks native function calls to hide common jailbreak packages and binaries. Also hooks ObjC jailbreak detection classes',
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    JS = '''\
var funcs=[];
var paths=[
        "/Applications/blackra1n.app",
        "/Applications/Cydia.app",
        "/Applications/FakeCarrier.app",
        "/Applications/Icy.app",
        "/Applications/IntelliScreen.app",
        "/Applications/MxTube.app",
        "/Applications/RockApp.app",
        "/Applications/SBSetttings.app",
        "/Applications/WinterBoard.app",
        "/bin/bash",
        "/bin/sh",
        "/bin/su",
        "/etc/apt",
        "/etc/ssh/sshd_config",
        "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
        "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/pguntether",
        "/private/var/lib/cydia",
        "/private/var/mobile/Library/SBSettings/Themes",
        "/private/var/stash",
        "/private/var/tmp/cydia.log",
        "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
        "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
        "/usr/bin/cycript",
        "/usr/bin/ssh",
        "/usr/bin/sshd",
        "/usr/libexec/sftp-server",
        "/usr/libexec/ssh-keysign",
        "/usr/sbin/frida-server",
        "/usr/sbin/sshd",
        "/var/cache/apt",
        "/var/lib/cydia",
        "/var/log/syslog",
        "/var/mobile/Media/.evasi0n7_installed",
        "/var/tmp/cydia.log"];

var libs = [
    "CYListenServer",
    "CYHandleClient",
    "MSHookFunction",
    "MSFindSymbol",
    "MSHookMessageEx",
    "MSHookProcess",
    "OBJC_CLASS_$_CYJSObject",
    "CYObjectiveC",
    "frida_agent_main"];

var resolver = new ApiResolver('objc');
resolver.enumerateMatches('*[* is*ailbroken]', {
    onMatch: function (match) {
        var func = match["name"];
        var ptr = match["address"];
        send("Found jailbreak detection method:  " + func);
        Interceptor.attach(ptr, {
            onEnter: function () {
                send("Hooking: " + func  +" to return false");
            },
            onLeave: function (retval) {
                retval.replace(0x0);
            }
        });
    },
    onComplete: function () {
    }   
});

var f = Module.findExportByName("libSystem.B.dylib","stat64");
Interceptor.attach(f, {
    onEnter: function ( args) {
        var arg = Memory.readUtf8String(args[0]);
        for (var path in paths) {
            if (arg.indexOf(paths[path]) > -1) {
                send("Hooking native function stat64: " + arg);
                return -1;
            }
        }
    },
});

var f = Module.findExportByName("libSystem.B.dylib","stat");
Interceptor.attach(f, {
    onEnter: function ( args) {
        var arg = Memory.readUtf8String(args[0]);
        for (var path in paths) {
            if (arg.indexOf(paths[path]) > -1) {
                send("Hooking native function stat: " + arg);
                return -1;
            }
        }
    },
});

var f = Module.findExportByName("libSystem.B.dylib","dlsym");
Interceptor.attach(f, {
    onEnter: function ( args) {
        var arg = Memory.readUtf8String(args[1]);
        for (var lib in libs) {
            if (arg.indexOf(libs[lib]) > -1) {
                send("Hooking native function dlsym: " + arg);
                return null;
            }
        }
    },
});

var f = Module.findExportByName("libSystem.B.dylib","open");
Interceptor.attach(f, {
    onEnter: function ( args) {
        var arg = Memory.readUtf8String(args[0]);
        for (var path in paths) {
            if (arg.indexOf(paths[path]) > -1) {
                send("Hooking native function open: " + arg);
                return -1;
            }
        }
    },
});

var f = Module.findExportByName("libSystem.B.dylib","fork");
Interceptor.attach(f, {
    onLeave: function (retval) {
        retval.replace(0x0);
    },
});
'''

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        FridaScript.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("frida_jb_detection_bypass.txt", self)

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
