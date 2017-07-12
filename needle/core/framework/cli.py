from __future__ import print_function
import os
import sys
import imp
import re
import urllib2

from ..utils.printer import Colors, Printer
from ..utils.constants import Constants
from framework import Framework, FrameworkException, Mode
from issues import IssueManager
from local_operations import LocalOperations

# Versioning
__author__ = Constants.AUTHOR
__email__ = Constants.EMAIL
__website__ = Constants.WEBSITE


# ======================================================================================================================
# CLI
# ======================================================================================================================
class CLI(Framework):
    """Main instance of Framework, and entry point of the program."""

    def __init__(self, mode):
        Framework.__init__(self, 'base')
        self._name = Constants.NAME
        self._mode = mode
        self._prompt_template = '{color_main}{main}{color_module}[{module}]{color_reset} > '
        self._base_prompt = self._prompt_template.format(color_main=Colors.C, main='',
                                                         color_module=Colors.O, module=self._name, color_reset=Colors.N)

        # Establish dynamic paths for framework elements
        self.path_app  = Framework.path_app = sys.path[0]
        self.path_core = Framework.path_core = os.path.join(self.path_app, 'core')
        self.path_libs = Framework.path_libs = os.path.join(self.path_app, 'libs')
        self.path_modules = Framework.path_modules = os.path.join(self.path_app, 'modules')

        # Init framework
        self.options = self._global_options
        self.show_banner()
        self._init_global_options()
        self._init_global_vars()
        self._init_home()
        self.do_reload(None)
        self._history_load()

    # ==================================================================================================================
    # INIT METHODS
    # ==================================================================================================================
    def _init_global_options(self):
        self.register_option('ip', Constants.GLOBAL_IP, True, 'IP address of the testing device (set to localhost to use USB)')
        self.register_option('port', Constants.GLOBAL_PORT, True, 'Port of the SSH agent on the testing device (needs to be != 22 to use USB)')
        self.register_option('agent_port', Constants.GLOBAL_AGENT_PORT, True, 'Port on which the Needle Agent is listening')
        self.register_option('username', Constants.GLOBAL_USERNAME, True, 'SSH Username of the testing device')
        self.register_option('password', Constants.PASSWORD_MASK, True, 'SSH Password of the testing device')
        self.register_option(Constants.PASSWORD_CLEAR, Constants.GLOBAL_PASSWORD, True, 'SSH Password of the testing device')
        self.register_option('pub_key_auth', Constants.GLOBAL_PUB_KEY_AUTH, True, 'Use public key auth to authenticate to the device. Key must be present in the ssh-agent if a passphrase is used')
        self.register_option('debug', Constants.GLOBAL_DEBUG, True, 'Enable debugging output')
        self.register_option('verbose', Constants.GLOBAL_VERBOSE, True, 'Enable verbose output')
        self.register_option('app', '', False, 'Bundle ID of the target application (e.g., com.example.app). Leave empty to launch wizard')
        self.register_option('output_folder', Constants.GLOBAL_OUTPUT_FOLDER, True, 'Full path of the output folder, where to store the output of the modules')
        self.register_option('save_history', Constants.GLOBAL_SAVE_HISTORY, True, 'Persists command history across sessions')
        self.register_option('skip_output_folder_check', Constants.GLOBAL_SKIP_OUTPUT_FOLDER_CHECK, False, 'Skip the check that ensures the output folder does not already contain other files. '
                                                                                                           'It will automatically overwrite any file')
        self.register_option('hide_system_apps', Constants.GLOBAL_HIDE_SYSTEM_APPS, True, 'If set to True, only 3rd party apps will be shown')

    def _init_global_vars(self):
        # Setup Printer
        self.printer = Framework.printer = Printer()
        self.printer.set_debug(self.options['debug'])
        self.printer.set_verbose(self.options['verbose'])
        # Setup pointers to other shared objects
        self.local_op = Framework.local_op = LocalOperations()
        self.device = Framework.device = None
        self.APP_METADATA = Framework.APP_METADATA = None
        self.ISSUE_LIST = Framework.ISSUE_MANAGER = IssueManager(self)

    def _init_home(self):
        # Folders to initialize
        self.path_home = Framework.path_home = Constants.FOLDER_HOME
        self.path_home_temp = Framework.path_home_temp = Constants.FOLDER_TEMP
        self.path_home_backup = Framework.path_home_backup = Constants.FOLDER_BACKUP
        init_folders = [self.path_home, self.path_home_temp, self.path_home_backup]
        # Initialize folders: home, temp, backup
        map(lambda x: os.makedirs(x), filter(lambda x: not os.path.exists(x), init_folders))

    def show_banner(self):
        banner='''
             __   _ _______ _______ ______         _______
             | \  | |______ |______ |     \ |      |______
             |  \_| |______ |______ |_____/ |_____ |______
        '''
        banner_len = len(max(banner.split('\n'), key=len))
        print(banner)
        print('{msg:^{lgh}}'.format(msg='%s %s v%s [%s]%s' % (Colors.G, self._name, Constants.VERSION, __website__, Colors.N),
                                    lgh=banner_len+8+8))
        print('{msg:^{lgh}}'.format(msg='%s[%s]%s' % (Colors.B, __author__, Colors.N),
                                    lgh=banner_len+8+8))
        print('')

    def version_check(self):
        try:
            pattern = "'(\d+\.\d+\.\d+[^']*)'"
            remote = re.search(pattern, urllib2.urlopen(Constants.VERSION_CHECK).read()).group(1)
            local = Constants.VERSION
            if local != remote:
                self.printer.error('Your version of {} does not match the latest release.'.format(Constants.NAME))
                self.printer.error('Please update or use the \'--no-check\' switch to continue using the old version.')
                self.printer.error('Local version: {}'.format(local))
                self.printer.error('Remote version: {}'.format(remote))
                return False
            else:
                return True
        except:
            return True

    # ==================================================================================================================
    # LOAD METHODS
    # ==================================================================================================================
    def _load_modules(self):
        self.loaded_category = {}
        self._loaded_modules = Framework._loaded_modules

        # Crawl the module directory and build the module tree
        for path in [os.path.join(x, 'modules') for x in (self.path_app, self.path_home)]:
            for dirpath, dirnames, filenames in os.walk(path):
                # Exclude hidden files and directories
                filenames = [f for f in filenames if not f[0] == '.']
                dirnames[:] = [d for d in dirnames if not d[0] == '.']
                if len(filenames) > 0:
                    for filename in [f for f in filenames if f.endswith('.py')]:
                        if 'unstable' in dirpath:
                            continue
                        is_loaded = self._load_module(dirpath, filename)
                        mod_category = 'disabled'
                        if is_loaded:
                            mod_category = re.search('/modules/([^/]*)', dirpath).group(1)
                        # store the resulting category statistics
                        if not mod_category in self.loaded_category:
                            self.loaded_category[mod_category] = 0
                        self.loaded_category[mod_category] += 1

    def _load_module(self, dirpath, filename):
        mod_name = filename.split('.')[0]
        if mod_name == '__init__':
            return
        mod_dispname = '/'.join(re.split('/modules/', dirpath)[-1].split('/') + [mod_name])
        mod_loadname = mod_dispname.replace('/', '_')
        mod_loadpath = os.path.join(dirpath, filename)
        mod_file = open(mod_loadpath)
        try:
            # import the module into memory
            mod = imp.load_source(mod_loadname, mod_loadpath, mod_file)
            __import__(mod_loadname)
            # add the module to the framework's loaded modules
            self._loaded_modules[mod_dispname] = sys.modules[mod_loadname].Module(mod_dispname)
            return True
        except ImportError as e:
            # notify the user of missing dependencies
            self.printer.error('Module \'%s\' disabled. Dependency required: \'%s\'' % (mod_dispname, e.message[16:]))
        except:
            # notify the user of errors
            self.print_exception()
            self.printer.error('Module \'%s\' disabled.' % mod_dispname)
        # remove the module from the framework's loaded modules
        self._loaded_modules.pop(mod_dispname, None)
        return False

    def do_load(self, params):
        """Loads specified module."""
        try:
            self._validate_options()
        except FrameworkException as e:
            self.printer.error(e.message)
            return
        if not params:
            self.help_load()
            return
        # finds any modules that contain params
        modules = [params] if params in self._loaded_modules else [x for x in self._loaded_modules if params in x]
        # notify the user if none or multiple modules are found
        if len(modules) != 1:
            if not modules:
                self.printer.error('Invalid module name.')
            else:
                self.printer.info('Multiple modules match \'%s\'.' % params)
                self.show_modules(modules)
            return
        # load the module
        mod_dispname = modules[0]
        # loop to support reload logic
        while True:
            y = self._loaded_modules[mod_dispname]
            mod_loadpath = os.path.abspath(sys.modules[y.__module__].__file__)
            # return the loaded module if in command line mode
            if self._mode == Mode.CLI:
                return y
            # begin a command loop
            y.prompt = self._prompt_template.format(color_main=Colors.C, main=self.prompt[:-3],
                                                    color_module=Colors.O, module=mod_dispname.split('/')[-1], color_reset=Colors.N)
            try:
                y.cmdloop()
            except KeyboardInterrupt:
                print('')
            if y._exit == 1:
                return True
            if y._reload == 1:
                self.printer.info('Reloading...')
                # reload the module in memory
                is_loaded = self._load_module(os.path.dirname(mod_loadpath), os.path.basename(mod_loadpath))
                if is_loaded:
                    continue
            break
    do_use = do_load

    def do_reload(self, params):
        """Reloads all modules."""
        self._load_modules()
