from __future__ import print_function
import os
import json
import time
import textwrap

from ..framework.framework import Framework, FrameworkException
from ..framework.options import Options
from ..utils.constants import Constants
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
        self.meta['path'] = os.path.join('modules', self._modulename) + '.py'
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

    def do_run(self, params, func=None):
        """Runs the module."""
        try:
            self._validate_options()
            # Execute PRE, and abort if we don't have an established connection
            pre = self.module_pre()
            if pre is None: return
            # Execute the module
            if func:
                func()
            else:
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
        self.device.setup()
        # Check if the module has been disabled for the current iOS version
        disabled_for_version = Constants.MODULES_DISABLED.get(self.device._ios_version)
        if disabled_for_version and self._modulename in disabled_for_version:
            raise FrameworkException('This module is not currently supported by the iOS version of the device in use (iOS {})'.format(self.device._ios_version))
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
            if content_type is dict:
                Utils.dict_print(content)
            elif Utils.is_plist(content):
                Utils.plist_print(content)
            elif content_type is list:
                map(print_screen, content)
            else:
                print('\t%s' % content.strip())

        def print_file(content):
            content_type = type(content)
            if content_type is dict:
                Utils.dict_write_to_file(content, fp)
            elif Utils.is_plist(content):
                Utils.plist_write_to_file(content, fp)
            elif content_type is list:
                map(print_file, content)
            else:
                fp.write('%s\n' % content.strip())

        if txt:
            # Print to screen
            if not silent:
                print_screen(txt)
            # Saving to file
            if outfile:
                if type(outfile) is not str:
                    self.printer.error("Please specify a valid path if you want to save to file")
                else:
                    self.printer.info("Saving output to file: {}".format(outfile))
                    with open(outfile, 'w') as fp:
                        print_file(txt)

    def validate_editor(self):
        """Check that the user entered a recognised editor in the PROGRAM option by seeing if it exists in the TOOLS_LOCAL directory."""
        if self.options['program'] in self.TOOLS_LOCAL:
             self.editor = self.TOOLS_LOCAL[self.options['program']]
        else:
            raise FrameworkException('The Editing program specified ("{}") is not supported.'.format(self.options['program']))

    def add_issue(self, name, content, confidence, outfile):
        """Wrapper for ISSUE_MANAGER.issue_add, which automatically fills the 'app' and 'module' fields."""
        # Check type of content
        if content is None:
            content = 'See the content of the linked file'
        if type(content) is list:
            content = '\n'.join(x.strip() for x in content)
        # Add issue
        self.ISSUE_MANAGER.issue_add(self.APP_METADATA['bundle_id'], self.meta['path'],
                                     name, content, self.ISSUE_MANAGER.CONFIDENCE_LEVELS[confidence], outfile)


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

    def __init__(self, params):
        FridaModule.__init__(self, params)
        # Add option for launch mode
        opt = ('spawn', False, True, 'If set to True, Frida will be used to spawn the app. '
                                    'If set to False, the app will be launched and Frida will be attached to the running instance')
        self.register_option(*opt)
        opt = ('resume', True, True, 'If set to True, Frida will resume the application process after spawning it (recommended)')
        self.register_option(*opt)

    def module_pre(self):
        def launch_spawn():
            # Launching the app
            self.printer.info("Spawning the app...")
            pid = device.spawn([self.APP_METADATA['bundle_id']])
            # Attaching to the process
            self.printer.info("Attaching to process: %s" % pid)
            self.session = device.attach(pid)
            if self.options['resume']:
                self.printer.verbose("Resuming the app's process...")
                device.resume(pid)
        def launch_attach():
            # Launching the app
            self.printer.info("Launching the app...")
            self.device.app.open(self.APP_METADATA['bundle_id'])
            binaryPath = self.APP_METADATA['binary_path'].replace("/private","")
            binaryPath = binaryPath.replace("'","")
            pid = self.device.app.search_pid(binaryPath)
            # Attaching to the process
            self.printer.info("Attaching to process: %s" % pid)
            self.session = device.attach(pid)

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
        # Spawn/attach to the process
        if self.options['spawn']:
            launch_spawn()
        else:
           launch_attach()
        # Prepare results
        self.results = []
        return 1

    def on_message(self, message, data):
        try:
            if message:
                try:
                    pld = json.loads(message["payload"])
                except:
                    pld = message["payload"]
                finally:
                    self.results.append(pld)
        except Exception as e:
            print(message)
            print(e)

    def print_cmd_output(self, silent=False):
        # Print to console
        if not silent:
            if not self.results:
                self.device.printer.warning('No results found!')
            for key in self.results:
                parsed = json.dumps(key, indent=4, sort_keys=True)
                self.device.printer.notify(parsed)
        # Print to file
        BaseModule.print_cmd_output(self, self.results, self.options['output'], silent=True)
