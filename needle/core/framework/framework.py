from __future__ import print_function
import os
import sys
import cmd
import codecs
import readline
import traceback

from options import Options
from ..device.device import Device
from ..utils.constants import Constants
from ..utils.menu import choose_from_list
from ..utils.printer import Colors
from ..utils.utils import Utils


# ======================================================================================================================
# FRAMEWORK EXCEPTION
# ======================================================================================================================
class FrameworkException(Exception):
    pass


# ======================================================================================================================
# MODE OF OPERATION
# ======================================================================================================================
class Mode(object):
    """Contains constants that represent the state of the interpreter."""
    CONSOLE = 0
    CLI     = 1
    GUI     = 2


# ======================================================================================================================
# FRAMEWORK CLASS
# ======================================================================================================================
class Framework(cmd.Cmd):
    # ==================================================================================================================
    # FRAMEWORK ATTRIBUTES
    # ==================================================================================================================
    # Framework Variables
    prompt = Constants.NAME_CLI
    _global_options = Options()
    _loaded_modules = {}
    _jobs = []
    _record = None
    _local_ready = False
    # Mode Flags
    _script = 0
    _load = 0
    # Path Constants
    path_app = ''
    path_core = ''
    path_libs = ''
    path_modules = ''
    path_home = ''
    path_home_temp = ''
    # Reference to External Objects
    local_op = None
    device = None
    APP_METADATA = None
    TOOLS_LOCAL = Constants.PATH_TOOLS_LOCAL

    # ==================================================================================================================
    # INIT
    # ==================================================================================================================
    def __init__(self, params):
        cmd.Cmd.__init__(self)
        self._modulename = params
        self.ruler = '-'
        self.spacer = '  '
        self.time_format = '%Y-%m-%d %H:%M:%S'
        self.nohelp = '%s[!] No help on %%s%s' % (Colors.R, Colors.N)
        self.do_help.__func__.__doc__ = '''Displays this menu'''
        self.doc_header = 'Commands (type [help|?] <topic>):'
        self.rpc_cache = []
        self._exit = 0

    # ==================================================================================================================
    # CMD OVERRIDE METHODS
    # ==================================================================================================================
    def default(self, line):
        self.do_shell_local(line)

    def emptyline(self):
        # disables running of last command when no command is given
        # return flag to tell interpreter to continue
        return 0

    def precmd(self, line):
        if Framework._load:
            print('\r', end='')
        if Framework._script:
            print('%s' % line)
        if Framework._record:
            recorder = codecs.open(Framework._record, 'ab', encoding='utf-8')
            recorder.write(('%s\n' % line).encode('utf-8'))
            recorder.flush()
            recorder.close()
        return line

    def onecmd(self, line):
        cmd, arg, line = self.parseline(line)
        if not line or line.startswith('#'):
            return self.emptyline()
        if line == 'EOF':
            # reset stdin for raw_input
            sys.stdin = sys.__stdin__
            Framework._script = 0
            Framework._load = 0
            self.printer.notify('Resource file successfully loaded')
            return 0
        if cmd is None:
            return self.default(line)
        self.lastcmd = line
        if cmd == '':
            return self.default(line)
        else:
            try:
                func = getattr(self, 'do_' + cmd)
            except AttributeError:
                return self.default(line)
            return func(arg)

    # ==================================================================================================================
    # COMPLETE METHODS
    # ==================================================================================================================
    def complete_load(self, text, *ignored):
        return [x for x in Framework._loaded_modules if x.startswith(text)]
    complete_use = complete_load

    def complete_set(self, text, *ignored):
        return [x.upper() for x in self.options if x.upper().startswith(text.upper())]
    complete_unset = complete_set

    def complete_show(self, text, line, *ignored):
        args = line.split()
        if len(args) > 1 and args[1].lower() == 'modules':
            if len(args) > 2: return [x for x in Framework._loaded_modules if x.startswith(args[2])]
            else: return [x for x in Framework._loaded_modules]
        options = sorted(self._get_show_names())
        return [x for x in options if x.startswith(text)]

    def _history_save(self):
        history_path = Constants.FILE_HISTORY
        try:
            if self._global_options['save_history']:
                self.printer.debug("Saving command history to: {}".format(history_path))
                readline.write_history_file(history_path)
        except Exception as e:
            self.printer.warning("Error while saving command history: {}".format(e))
            self.printer.warning("Continuing anyway...")

    def _history_load(self):
        history_path = Constants.FILE_HISTORY
        if os.path.exists(history_path):
            self.printer.debug("Trying to load command history from: {}".format(history_path))
            readline.read_history_file(history_path)
        else:
            self.printer.debug("Command history not found in: {}".format(history_path))

    # ==================================================================================================================
    # OUTPUT METHODS
    # ==================================================================================================================
    def print_exception(self, line=''):
        if self._global_options['debug']:
            print('%s%s' % (Colors.R, '-'*60))
            traceback.print_exc()
            print('%s%s' % ('-'*60, Colors.N))
        line = ' '.join([x for x in [traceback.format_exc().strip().splitlines()[-1], line] if x])
        self.printer.error(line)

    def print_heading(self, line, level=1):
        """Formats and presents styled header text."""
        line = Utils.to_unicode(line)
        print('')
        if level == 0:
            print(self.ruler*len(line))
            print(line.upper())
            print(self.ruler*len(line))
        if level == 1:
            print('%s%s' % (self.spacer, line.title()))
            print('%s%s' % (self.spacer, self.ruler*len(line)))

    def print_table(self, data, header=[], title=''):
        """Accepts a list of rows and outputs a table."""
        tdata = list(data)
        if header:
            tdata.insert(0, header)
        if len(set([len(x) for x in tdata])) > 1:
            raise FrameworkException('Row lengths not consistent.')
        lens = []
        cols = len(tdata[0])
        # create a list of max widths for each column
        for i in range(0,cols):
            lens.append(len(max([Utils.to_unicode_str(x[i]) if x[i] != None else '' for x in tdata], key=len)))
        # calculate dynamic widths based on the title
        title_len = len(title)
        tdata_len = sum(lens) + (3*(cols-1))
        diff = title_len - tdata_len
        if diff > 0:
            diff_per = diff / cols
            lens = [x+diff_per for x in lens]
            diff_mod = diff % cols
            for x in range(0, diff_mod):
                lens[x] += 1
        # build ascii table
        if len(tdata) > 0:
            separator_str = '%s+-%s%%s-+' % (self.spacer, '%s---'*(cols-1))
            separator_sub = tuple(['-'*x for x in lens])
            separator = separator_str % separator_sub
            data_str = '%s| %s%%s |' % (self.spacer, '%s | '*(cols-1))
            # top of ascii table
            print('')
            print(separator)
            # ascii table data
            if title:
                print('%s| %s |' % (self.spacer, title.center(tdata_len)))
                print(separator)
            if header:
                rdata = tdata.pop(0)
                data_sub = tuple([rdata[i].center(lens[i]) for i in range(0,cols)])
                print(data_str % data_sub)
                print(separator)
            for rdata in tdata:
                data_sub = tuple([Utils.to_unicode_str(rdata[i]).ljust(lens[i])
                                  if rdata[i] is not None else ''.ljust(lens[i]) for i in range(0, cols)])
                print(data_str % data_sub)
            # bottom of ascii table
            print(separator)
            print('')

    # ==================================================================================================================
    # SHOW METHODS
    # ==================================================================================================================
    def show_modules(self, param):
        """Show list of available Modules."""
        # Process parameter according to type
        if type(param) is list:
            modules = param
        elif param:
            modules = [x for x in Framework._loaded_modules if x.startswith(param)]
            if not modules:
                self.printer.error('Invalid module category.')
                return
        else:
            modules = Framework._loaded_modules
        # Display the modules
        last_category = ''
        for module in sorted(modules):
            category = module.split('/')[0]
            if category != last_category:
                # Print header
                last_category = category
                self.print_heading(last_category)
            # Print module
            print('%s%s' % (self.spacer*2, module))
        print('')

    def show_options(self, options=None):
        """Show list of available Options."""
        if options is None:
            options = self.options
        if options:
            pattern = '%s%%s  %%s  %%s  %%s' % (self.spacer)
            key_len = len(max(options, key=len))
            if key_len < 4:
                key_len = 4
            val_len = len(max([Utils.to_unicode_str(options[x]) for x in options], key=len))
            if val_len < 13:
                val_len = 13
            print('')
            print(pattern % ('Name'.ljust(key_len), 'Current Value'.ljust(val_len), 'Required', 'Description'))
            print(pattern % (self.ruler*key_len, (self.ruler*13).ljust(val_len), self.ruler*8, self.ruler*11))
            for key in sorted(options):
                if not key == Constants.PASSWORD_CLEAR:
                    value = options[key] if options[key] != None else ''
                    reqd = 'no' if options.required[key] is False else 'yes'
                    desc = options.description[key]
                    print(pattern % (key.upper().ljust(key_len), Utils.to_unicode_str(value).ljust(val_len),
                                     Utils.to_unicode_str(reqd).ljust(8), desc))
            print('')
        else:
            print('')
            print('%sNo options available for this module.' % self.spacer)
            print('')

    def _get_show_names(self):
        """Any method beginning with "show_" will be parsed and added as a subcommand for the show command."""
        prefix = 'show_'
        return [x[len(prefix):] for x in self.get_names() if x.startswith(prefix)]

    # ==================================================================================================================
    # HELP METHODS
    # ==================================================================================================================
    def help_load(self):
        print(getattr(self, 'do_load').__doc__)
        print('')
        print('Usage: [load|use] <module>')
        print('')
    help_use = help_load

    def help_resource(self):
        print(getattr(self, 'do_resource').__doc__)
        print('')
        print('Usage: resource <filename>')
        print('')

    def help_search(self):
        print(getattr(self, 'do_search').__doc__)
        print('')
        print('Usage: search <string>')
        print('')

    def help_set(self):
        print(getattr(self, 'do_set').__doc__)
        print('')
        print('Usage: set <option> <value>')
        self.show_options()

    def help_unset(self):
        print(getattr(self, 'do_unset').__doc__)
        print('')
        print('Usage: unset <option>')
        self.show_options()

    def help_shell_local(self):
        print(getattr(self, 'do_shell_local').__doc__)
        print('')
        print('Usage: <local command>')
        print('...just type a command at the prompt.')
        print('')

    def help_shell(self):
        print(getattr(self, 'do_shell').__doc__)
        print('')
        print('Usage: shell')
        print('...drop a remote shell on the device.')
        print('')

    def help_show(self):
        options = sorted(self._get_show_names())
        print(getattr(self, 'do_show').__doc__)
        print('')
        print('Usage: show [%s]' % ('|'.join(options)))
        print('')

    def help_jobs(self):
        print(getattr(self, 'do_jobs').__doc__)
        print('')
        print('Usage: jobs')
        print('...list background jobs currently running.')
        print('')

    def help_kill(self):
        print(getattr(self, 'do_kill').__doc__)
        print('')
        print('Usage: kill <job number>')
        print('...stop the background job specified.')
        print('')

    def help_issues(self):
        print(getattr(self, 'do_issues').__doc__)
        print('')
        print('Usage: issues')
        print('...list the issues already identified.')
        print('')

    def help_add_issue(self):
        print(getattr(self, 'do_add_issue').__doc__)
        print('')
        print('Usage: add_issue')
        print('...start a wizard that will allow to manually add an issue.')
        print('')

    # ==================================================================================================================
    # OPTIONS METHODS
    # ==================================================================================================================
    def _validate_options(self):
        for option in self.options:
            # if value type is bool or int, then we know the options is set
            if not type(self.options[option]) in [bool, int]:
                if self.options.required[option] is True and not self.options[option]:
                    if option == Constants.PASSWORD_CLEAR:
                        option = 'password'.upper()
                    raise FrameworkException('Value required for the \'%s\' option.' % (option.upper()))
        return

    def register_option(self, name, value, required, description):
        self.options.init_option(name=name.lower(), value=value, required=required, description=description)

    # ==================================================================================================================
    # COMMAND METHODS
    # ==================================================================================================================
    def do_exit(self, params):
        """Stop background jobs, cleanup temp folders (local&remote), close connection, then exits the Framework."""
        # Save history
        self._history_save()
        # Stop background jobs
        for i in xrange(len(self._jobs)):
            self.do_kill(i)
        # Stop Frida
        if self.device and self.device._frida_server:
            self.device._portforward_frida_stop()
            self.local_op.dir_delete(os.path.join(self.path_app, '__handlers__'))
        # Cleanup temp folders
        try:
            # Cleanup local temp folder
            self.printer.verbose("Cleaning local temp folder: %s" % self.path_home_temp)
            self.local_op.dir_delete(self.path_home_temp)
            # Cleanup remote temp folder
            if self.device:
                self.device.cleanup()
                # Disconnect from device
                self.device.disconnect()
        except Exception as e:
            self.printer.warning("Problem while cleaning up temp folders, ignoring: %s - %s " % (type(e).__name__, e.message))
        finally:
            # Exit
            self._exit = 1
            return True

    def do_back(self, params):
        """Exits the current context."""
        return True

    def do_info(self, params):
        """Alias: info == show info."""
        if hasattr(self, 'show_info'):
            self.show_info()

    def do_set(self, params):
        """Sets module options."""
        options = params.split()
        if len(options) < 2:
            self.help_set()
            return
        name = options[0].lower()
        if name in self.options:
            value = ' '.join(options[1:])

            if name == 'password':
                self.options[Constants.PASSWORD_CLEAR] = value
                value = Constants.PASSWORD_MASK

            # Actual set
            self.options[name] = value
            print('%s => %s' % (name.upper(), value))

            # Check verbosity level
            if name == 'debug':
                self.printer.set_debug(self.options['debug'])
            if name == 'verbose':
                self.printer.set_verbose(self.options['verbose'])
                if self.options['verbose'] is False:
                    self.options['debug'] = False
                    self.printer.set_debug(self.options['debug'])
            # Reset output folder
            if name == 'output_folder':
                self.printer.debug("Output folder changed, reloading modules")
                self._local_ready = Framework._local_ready = False
                self.do_reload(None)
        else:
            self.printer.error('Invalid option.')

    def do_unset(self, params):
        """Unsets module options."""
        self.do_set('%s %s' % (params, 'None'))

    def do_show(self, params):
        """Shows various framework items."""
        if not params:
            self.help_show()
            return
        params = params.lower().split()
        arg = params[0]
        params = ' '.join(params[1:])
        if arg in self._get_show_names():
            func = getattr(self, 'show_' + arg)
            if arg == 'modules':
                func(params)
            else:
                func()
        else:
            self.help_show()

    def do_search(self, params):
        """Searches available modules."""
        if not params:
            self.help_search()
            return
        text = params.split()[0]
        self.printer.info('Searching for "%s"...' % (text))
        modules = [x for x in Framework._loaded_modules if text in x]
        if not modules:
            self.printer.error('No modules found containing \'%s\'.' % (text))
        else:
            self.show_modules(modules)

    def do_resource(self, params):
        """Executes commands from a resource file."""
        if not params:
            self.help_resource()
            return
        if os.path.exists(params):
            self.printer.info('Loading commands from resource file')
            sys.stdin = open(params)
            Framework._script = 1
        else:
            self.printer.error('Script file "%s" not found.' % (params))

    def do_load(self, params):
        """Loads selected module."""
        if not params:
            self.help_load()
            return
        # Finds any modules that contain params
        modules = [params] if params in Framework._loaded_modules else [x for x in Framework._loaded_modules if params in x]
        # Notify the user if none or multiple modules are found
        if len(modules) != 1:
            if not modules:
                self.printer.error('Invalid module name.')
            else:
                self.printer.info('Multiple modules match "%s".' % params)
                self.show_modules(modules)
            return
        import StringIO
        # Compensation for stdin being used for scripting and loading
        if Framework._script:
            end_string = sys.stdin.read()
        else:
            end_string = 'EOF'
            Framework._load = 1
        sys.stdin = StringIO.StringIO('load %s\n%s' % (modules[0], end_string))
        return True
    do_use = do_load

    def do_shell_local(self, params):
        """Executes local shell commands."""
        self.printer.info('Executing Local Command: %s' % (params))
        out, err = self.local_op.command_blocking(params)
        if out: print('%s%s%s' % (Colors.O, out, Colors.N), end='')
        if err: print('%s%s%s' % (Colors.R, err, Colors.N), end='')

    def do_shell(self, params):
        """Drop a remote shell on the device."""
        self.printer.info("Spawning a shell...")
        if self.connection_check():
            self.device.shell()

    def do_exec_command(self, params):
        """Execute a single command on the remote device."""
        if not self.connection_check():
            return None
        self.printer.info("Executing: %s" % params)
        self.device.remote_op.command_blocking(params, internal=False)

    def do_pull(self, params):
        """Pull a file from the device."""
        if not self.connection_check():
            return None
        a, b = Utils.extract_paths_from_string(params)
        if a is None:
            self.printer.error('Please enclose the paths in (double) quotes correctly')
            return None
        self.device.pull(a, b)

    def do_push(self, params):
        """Push a file on the device."""
        if not self.connection_check():
            return None
        a, b = Utils.extract_paths_from_string(params)
        if a is None:
            self.printer.error('Please enclose the paths in (double) quotes correctly')
            return None
        self.device.push(a, b)

    def do_jobs(self, params):
        """List running backgrond jobs."""
        if self._jobs:
            self.printer.notify("Running jobs:")
            names = [j.__module__ for j in self._jobs]
            choose_from_list(names, choose=False)
        else:
            self.printer.info("No running jobs")

    def do_kill(self, params):
        """Stop running background job."""
        # Select chosen job
        try:
            num = int(params)
            job = self._jobs[num]
        except IndexError:
            self.printer.error("Error while killing job: no job attached to the selected job number")
        except ValueError:
            self.printer.error("Please enter a correct number")
        # Run the module_kill method of the job
        try:
            job.module_kill()
        except Exception:
            self.printer.info("Error when trying to invoke 'module_kill'. Doing nothing...")
            self.print_exception()
        # Remove job from the list
        try:
            del self._jobs[num]
        except KeyError:
            self.printer.error("Error while killing job: no job attached to the selected job number. Continuing...")
        except Exception:
            self.print_exception()

    def do_issues(self, params):
        """List currently gathered issues."""
        self.ISSUE_MANAGER.issue_print()

    def do_add_issue(self, params):
        """Prompt the user to manually add an issue."""
        self.ISSUE_MANAGER.issue_add_manual()

    # ==================================================================================================================
    # CONNECTION METHODS
    # ==================================================================================================================
    def _parse_device_options(self):
        """Parse device options from the _global_options and return them."""
        IP = self._global_options['ip']
        PORT = self._global_options['port']
        AGENT_PORT = self._global_options['agent_port']
        USERNAME = self._global_options['username']
        PASSWORD = self._global_options[Constants.PASSWORD_CLEAR]
        PUB_KEY_AUTH = self._global_options['pub_key_auth']
        return IP, PORT, AGENT_PORT, USERNAME, PASSWORD, PUB_KEY_AUTH

    def _spawn_device(self):
        """Instantiate a new Device object, and open a connection."""
        IP, PORT, AGENT_PORT, USERNAME, PASSWORD, PUB_KEY_AUTH = self._parse_device_options()
        self.device = Framework.device = Device(IP, PORT, AGENT_PORT, USERNAME, PASSWORD, PUB_KEY_AUTH, self.TOOLS_LOCAL)

    def _connection_new(self):
        """Try to instantiate a new connection with the device."""
        try:
            self._spawn_device()
            self.device.connect()
        except Exception as e:
            self.printer.error("Problem establishing connection: %s - %s " % (type(e).__name__, e.message))
            self.print_exception()
            self.device.disconnect()
            self.device = Framework.device = None
            return None
        return self.device

    def connection_check(self):
        """Check if a connection with the device is already up and running, otherwise create a new connection."""
        self.printer.info("Checking connection with device...")
        if self.device is None:
            self.printer.verbose('Connection not present, creating a new instance')
            return self._connection_new()
        else:
            # Check connection we have is with the current chosen IP, PORT, USERNAME, PASSWORD, PUB_KEY_AUTH
            if self._global_options['ip'] != self.device._ip or \
               self._global_options['port'] != self.device._port or \
               self._global_options['username'] != self.device._username or \
               self._global_options[Constants.PASSWORD_CLEAR] != self.device._password or \
               self._global_options['pub_key_auth'] != self.device._pub_key_auth:

                self.printer.verbose('Settings changed in global options. Establishing a new connection')
                self.device = Framework.device = None
                return self._connection_new()
            else:
                self.printer.notify("Already connected to: %s" % self._global_options['ip'])
                return 1

    # ==================================================================================================================
    # APP METHODS
    # ==================================================================================================================
    def app_check(self):
        """Check if a target app has been selected, otherwise launch a wizard. Then retrieve its metadata."""
        app = self._global_options['app']
        # Target app not selected, launch wizard
        if not app:
            self.printer.info('Target app not selected. Launching wizard...')
            self.device._list_apps(self._global_options['hide_system_apps'])
            app = self.device.select_target_app()
            self._global_options['app'] = app
            if app is None:
                self.printer.error('Error selecting app. Please retry.')
                return None
        # Metadata
        self.printer.notify('Target app: %s' % app)
        if not self.APP_METADATA or self.APP_METADATA['bundle_id'] != app:
            # Metadata not yet fetched, retrieve it
            self.printer.info("Retrieving app's metadata...")
            if self.device._applist is None:
                self.device._list_apps(self._global_options['hide_system_apps'])
            self.APP_METADATA = Framework.APP_METADATA = self.device.app.get_metadata(app)
        return app
