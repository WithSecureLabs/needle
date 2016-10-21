from __future__ import print_function
import os
import time
import json
import plistlib
import textwrap
from pprint import pprint

from ..framework.framework import Framework, FrameworkException
from ..framework.options import Options
from ..utils.printer import Colors
from ..utils.utils import Utils


# ======================================================================================================================
# MODULE CLASS
# ======================================================================================================================
class BaseModule(Framework):
    # Module Variables
    meta = {}

    def __init__(self, params):
        Framework.__init__(self, params)
        self.options = Options()
        # Register all other specified options
        if 'options' in self.meta:
            for option in self.meta['options']:
                self.register_option(*option)
        self._reload = 0

    # ==================================================================================================================
    # OPTIONS METHODS
    # ==================================================================================================================
    def _get_source(self, params, query=None):
        if os.path.exists(params):
            sources = open(params).read().split()
        else:
            sources = [params]
        source = [Utils.to_unicode(x) for x in sources]
        if not source:
            raise FrameworkException('Source contains no input.')
        return source

    # ==================================================================================================================
    # SHOW METHODS
    # ==================================================================================================================
    def show_source(self):
        filename = None
        for path in [os.path.join(x, 'modules', self._modulename) + '.py' for x in (self.path_app, self.path_home)]:
            if os.path.exists(path):
                filename = path
        if filename:
            with open(filename) as f:
                content = f.readlines()
                nums = [str(x) for x in range(1, len(content)+1)]
                num_len = len(max(nums, key=len))
                for num in nums:
                    print('%s|%s' % (num.rjust(num_len), content[int(num)-1]), end='')
        else:
            self.printer.info('Show source not available for this module.')

    def show_info(self):
        self.meta['path'] = os.path.join('modules', self._modulename) + '.py'
        print('')
        # Meta info
        for item in ['name', 'path', 'author', 'version']:
            if item in self.meta:
                print('%s%s%s: %s' % (Colors.O, item.title().rjust(10), Colors.N, self.meta[item]))
        print('')
        # Description
        if 'description' in self.meta:
            print('%sDescription:%s' % (Colors.O, Colors.N))
            print('%s%s' % (self.spacer, textwrap.fill(self.meta['description'], 100, subsequent_indent=self.spacer)))
            print('')
        # Comments
        if 'comments' in self.meta:
            print('%sComments:%s' % (Colors.O, Colors.N))
            for comment in self.meta['comments']:
                prefix = '* '
                if comment.startswith('\t'):
                    prefix = self.spacer+'- '
                    comment = comment[1:]
                print('%s%s' % (self.spacer, textwrap.fill(prefix+comment, 100, subsequent_indent=self.spacer)))
            print('')
        # Options
        print('%sOptions:%s' % (Colors.O, Colors.N), end='')
        self.show_options()
        # sources
        if hasattr(self, '_default_source'):
            print('%sSource Options:%s' % (Colors.O, Colors.N))
            print('%s%s%s' % (self.spacer, 'default'.ljust(15), self._default_source))
            print('%s%sstring representing a single input' % (self.spacer, '<string>'.ljust(15)))
            print('%s%spath to a file containing a list of inputs' % (self.spacer, '<path>'.ljust(15)))
            print('')

    def show_globals(self):
        self.show_options(self._global_options)

    # ==================================================================================================================
    # COMMAND METHODS
    # ==================================================================================================================
    def do_reload(self, params):
        """Reloads the current module."""
        self._reload = 1
        return True

    def do_run(self, params):
        """Runs the module."""
        try:
            self._validate_options()
            # Execute PRE, and abort if we don't have an established connection
            pre = self.module_pre()
            if pre is None: return
            # Execute the module
            self.module_run()
            # Execute POST
            self.module_post()
        except KeyboardInterrupt:
            print('')
        except Exception:
            self.print_exception()

    def module_pre(self, bypass_app=False):
        """Execute before module_run"""
        # Setup local output folder
        if not self._local_ready:
            self.printer.debug("Setup local output folder: {}".format(self._global_options['output_folder']))
            self.local_op.output_folder_setup(self)
            self._local_ready = Framework._local_ready = True
        # If it's a StaticModule, bypass any other check
        if isinstance(self, StaticModule):
            self.printer.verbose("Static Module, connection not needed...")
            return 1
        # Check if we have an established connection, otherwise abort the run
        if self.connection_check() is None: return None
        # Setup device
        self.device.setup(self._global_options['setup_device'])
        # If not specified to bypass app check
        if not bypass_app:
            # Check target app, otherwise launch wizard
            if self.app_check() is None: return None
        # Everything set
        return 1

    def module_run(self):
        """Actual execution."""
        pass

    def module_post(self):
        """Execute after module_run"""
        pass

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def print_cmd_output(self, txt, outfile=None, silent=False):
        """Pretty print output coming from command execution. Also save it to file if specified"""
        def print_screen(content):
            content_type = type(content)
            if content_type is dict or content_type is plistlib._InternalDict: pprint(content, indent=4)
            elif content_type is list: map(print_screen, content)
            else: print('\t%s' % content)

        def print_file(content):
            content_type = type(content)
            if content_type is dict or content_type is plistlib._InternalDict:
                try: json.dump(content, fp)
                except TypeError: pass
            elif content_type is list:
                for line in content: fp.write('%s\n' % line)
            else:
                fp.write('%s\n' % content)

        if txt:
            # Print to screen
            if not silent: print_screen(txt)
            # Saving to file
            if outfile:
                if type(outfile) is not str:
                    self.printer.error("Please specify a valid path if you want to save to file")
                else:
                    self.printer.info("Saving output to file: %s" % outfile)
                    with open(outfile, 'w') as fp:
                        print_file(txt)

# ======================================================================================================================
# OTHER TYPES OF MODULES
# ======================================================================================================================
class StaticModule(BaseModule):
    """To be used for modules that do not require a connection with the device."""
    def __init__(self, params):
        BaseModule.__init__(self, params)


class BackgroundModule(BaseModule):
    """To be used for background processes (jobs)."""
    def __init__(self, params):
        BaseModule.__init__(self, params)

    def module_post(self):
        """Add module to the list of running jobs"""
        self._jobs.append(self)


class DebugModule(BaseModule):
    """To be used for modules relying on LLDB."""
    def __init__(self, params):
        BaseModule.__init__(self, params)

    def module_pre(self):
        """Setting up port forwarding"""
        res = BaseModule.module_pre(self)
        if res:
            if not self.device._debug_server:
                self.printer.info("Setting up local port forwarding to enable communications with the Debug server...")
                self.device._portforward_debug_start()
                time.sleep(1)
                return 1
            else:
                self.printer.info("Local port forwarding to enable communications with the Debug server already setup")
                return 1
        return res

    def module_post(self):
        pass


class FridaModule(BaseModule):
    """To be used for modules relying on Frida."""
    def __init__(self, params):
        BaseModule.__init__(self, params)

    def module_pre(self):
        """Setting up port forwarding"""
        res = BaseModule.module_pre(self)
        if res:
            if not self.device._frida_server:
                self.printer.info("Setting up local port forwarding to enable communications with the Frida server...")
                self.device._portforward_frida_start()
                time.sleep(1)
                return 1
            else:
                self.printer.info("Local port forwarding to enable communications with the Frida server already setup")
                return 1
        return res

    def module_post(self):
        pass


class FridaScript(FridaModule):
    """To be used for modules that just needs to execute a JS payload."""
    def module_pre(self):
        # Run FridaModule setup function
        FridaModule.module_pre(self)

        # Get an handle to the device
        import frida
        if self.device.is_usb():
            self.printer.debug("Connected over USB")
            device = frida.get_usb_device()
        else:
            self.printer.debug("Connected over Wi-Fi")
            device = frida.get_device_manager().enumerate_devices()[1]

        # Launching the app
        self.printer.info("Launching the app...")
        self.device.app.open(self.APP_METADATA['bundle_id'])
        pid = int(self.device.app.search_pid(self.APP_METADATA['name']))

        # Attaching to the process
        self.printer.info("Attaching to process: %s" % pid)
        self.session = device.attach(pid)
        return 1

    def on_message(self, message, data):
        try:
            if message:
                print("[*] {0}".format(message["payload"]))
                self.output.append(message["payload"])
        except Exception as e:
            print(message)
            print(e)
