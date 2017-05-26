from core.framework.module import BaseModule
from core.utils.constants import Constants
from core.utils.utils import Utils
from core.utils.menu import choose_boolean

import string


class Module(BaseModule):
    meta = {
        'name': 'Dependency Installer',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Automatically checks if all the dependencies needed are already present on the device, otherwise it will install them",
        'options': (
            ('ALL', False, True, 'Set to True to install all listed tools.'),
        ),
        'comments': ['These are requirements that needs to be already installed on the device: APT 0.7 Strict, dpkg']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        self._packagelist = []
        self._cydialist = []
        tools = Constants.DEVICE_SETUP['TOOLS']
        installable = dict([(k, v) for k, v in tools.iteritems()
                            if v['PACKAGES'] is not None or v['LOCAL'] is not None or v['SETUP'] is not None])
        for t in installable:
            opt = (t, False, True, 'Set to True to install: {}.'.format(t))
            self.register_option(*opt)

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # INSTALL PACKAGE
    # ==================================================================================================================
    def __apt_update(self):
        try:
            cmd = '{apt} update'.format(apt=Constants.DEVICE_TOOLS['APT-GET'])
            self.device.remote_op.command_blocking(cmd, internal=True)
        except Exception as e:
            self.device.printer.warning('Error occurred during apt-get update: %s' % e.message.strip())
            self.device.printer.warning('Trying to continue anyway...')

    def __apt_add_repo(self, repo):
        """Add the specified repo to cydia.list."""
        if repo in self._cydialist:
            self.device.printer.debug('Repo already in cydia.list: %s' % repo)
            return
        try:
            self.device.printer.debug('Adding repo to cydia.list: %s' % repo)
            cmd = 'echo "deb {repo} ./" >> {cydialist}'.format(repo=repo, cydialist=Constants.CYDIA_LIST)
            self.device.remote_op.command_blocking(cmd, internal=True)
            self.__apt_update()
        except Exception as e:
            self.device.printer.warning('Error occurred while adding a new repo: %s' % e.message.strip())
            self.device.printer.warning('Trying to continue anyway...')

    def __apt_install(self, package):
        """Install the given package using apt-get."""
        cmd = '{apt} install -y --force-yes {package}'.format(apt=Constants.DEVICE_TOOLS['APT-GET'], package=package)
        self.device.remote_op.command_blocking(cmd, internal=True)

    def __install_package(self, toolname, tool):
        """Check if the package is already installed, otherwise add repo (if any) and use apt-get to install it."""
        packages, repo = tool['PACKAGES'], tool['REPO']
        for pk in packages:
            if pk in self._packagelist:
                self.device.printer.debug('[INSTALL] Already installed: %s.' % pk)
            else:
                self.device.printer.verbose('[INSTALL] Installing %s via apt-get.' % toolname)
                if repo: self.__apt_add_repo(repo)
                self.__apt_install(pk)

    # ==================================================================================================================
    # INSTALL LOCAL
    # ==================================================================================================================
    def __is_tool_available(self, tool):
        """Return true if the tool is installed on the device."""
        cmd = '{which} {tool}'.format(which=Constants.DEVICE_TOOLS['WHICH'], tool=tool)
        out = self.device.remote_op.command_blocking(cmd, internal=True)
        return True if out else False

    def __install_local(self, toolname, tool):
        """Push the binary from the workstation to the device"""
        local, command = tool['LOCAL'], tool['COMMAND']
        name = Utils.extract_filename_from_path(command)
        if not self.__is_tool_available(name):
            self.device.printer.verbose('[INSTALL] Manually installing: %s' % toolname)
            src = local
            dst = Utils.path_join('/usr/bin/', name)
            self.device.push(src, dst)
            self.device.remote_op.chmod_x(dst)
        else:
            self.device.printer.debug('[INSTALL] Tool already available: %s' % toolname)

    # ==================================================================================================================
    #  INSTALL COMMANDS
    # ==================================================================================================================
    def __install_commands(self, toolname, tool):
        """Use a list of commands to install the tool"""
        local, setup = tool['LOCAL'], tool['SETUP']
        self.device.printer.verbose('[INSTALL] Manually installing: %s' % toolname)
        for cmd in setup:
            self.device.remote_op.command_blocking(cmd)

    # ==================================================================================================================
    # CHECKERS AND CONFIGURATORS
    # ==================================================================================================================
    def _check_prerequisites(self):
        """Check if the prerequisites have been satisfied."""
        self.device.printer.info("Checking prerequisites...")
        for tool in Constants.DEVICE_SETUP['PREREQUISITES']:
            if not self.__is_tool_available(tool):
                self.device.printer.error('Prerequisite Not Found: %s ' % tool)
                raise Exception('Please install the requirements listed in the README file')

    def _refresh_package_list(self):
        """Refresh the list of installed packages."""
        self.device.printer.info("Refreshing package list...")
        cmd = '{dpkg} --get-selections | grep -v "deinstall" | cut -f1'.format(dpkg=Constants.DEVICE_TOOLS['DPKG'])
        out = self.device.remote_op.command_blocking(cmd, internal=True)
        self._packagelist = map(string.strip, out)

    def _parse_cydia_list(self):
        """Retrieve the content of the cydia.list file."""
        self.__apt_update()
        cmd = 'cat {cydialist}'.format(cydialist=Constants.CYDIA_LIST)
        out = self.device.remote_op.command_blocking(cmd, internal=True)
        self._cydialist = out

    def _configure_tool(self, toolname):
        """Check if the specified tool is already on the device, otherwise install it."""
        # Retrieve install options
        tool = Constants.DEVICE_SETUP['TOOLS'][toolname]
        try:
            if tool['PACKAGES']:
                # Install via apt-get
                self.__install_package(toolname, tool)
            elif tool['LOCAL']:
                # Manual install
                self.__install_local(toolname, tool)
            elif tool['SETUP']:
                # Use list of commands
                self.__install_commands(toolname, tool)
            else:
                self.device.printer.debug('Installation method not provided for %s. Skipping' % toolname)
        except Exception as e:
            self.device.printer.warning('Error occurred during installation of tools: %s' % e.message.strip())
            self.device.printer.warning('Trying to continue anyway...')

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Configure device: check prerequisites and install missing tools."""
        # Check Prerequisites
        self._check_prerequisites()

        # Installing coreutils
        self._configure_tool('COREUTILS')

        # Refresh package list
        self.__apt_update()
        self._refresh_package_list()
        self._parse_cydia_list()

        # Get list of tools to install
        if self.options['all']:
            to_install = [k.upper() for k, v in self.options.iteritems()]
        else:
            to_install = [k.upper() for k, v in self.options.iteritems() if v]
        if 'ALL' in to_install:
            to_install.remove('ALL')
        self.printer.info('The following tools are going to be installed: {}'.format(to_install))

        # Configure tools
        if choose_boolean('Do you want to continue?'):
            map(self._configure_tool, to_install)
