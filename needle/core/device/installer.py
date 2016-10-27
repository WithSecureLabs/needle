import os
import string

from ..utils.constants import Constants
from ..utils.utils import Utils


class Installer(object):
    def __init__(self, device):
        self._device = device
        self._packagelist = []
        self._cydialist = []

    # ==================================================================================================================
    # INSTALL PACKAGE
    # ==================================================================================================================
    def __apt_update(self):
        try:
            cmd = '{apt} update'.format(apt=Constants.DEVICE_TOOLS['APT-GET'])
            self._device.remote_op.command_blocking(cmd, internal=True)
        except Exception as e:
            self._device.printer.warning('Error occurred during apt-get update: %s' % e.message.strip())
            self._device.printer.warning('Trying to continue anyway...')

    def __apt_add_repo(self, repo):
        """Add the specified repo to cydia.list."""
        if repo in self._cydialist:
            self._device.printer.debug('Repo already in cydia.list: %s' % repo)
            return
        try:
            self._device.printer.debug('Adding repo to cydia.list: %s' % repo)
            cmd = 'echo "deb {repo} ./" >> {cydialist}'.format(repo=repo, cydialist=Constants.CYDIA_LIST)
            self._device.remote_op.command_blocking(cmd, internal=True)
            self.__apt_update()
        except Exception as e:
            self._device.printer.warning('Error occurred while adding a new repo: %s' % e.message.strip())
            self._device.printer.warning('Trying to continue anyway...')

    def __apt_install(self, package):
        """Install the given package using apt-get."""
        cmd = '{apt} install -y --force-yes {package}'.format(apt=Constants.DEVICE_TOOLS['APT-GET'], package=package)
        self._device.remote_op.command_blocking(cmd, internal=True)

    def __install_package(self, toolname, tool):
        """Check if the package is already installed, otherwise add repo (if any) and use apt-get to install it."""
        packages, repo = tool['PACKAGES'], tool['REPO']
        for pk in packages:
            if pk in self._packagelist:
                self._device.printer.debug('[INSTALL] Already installed: %s.' % toolname)
            else:
                self._device.printer.verbose('[INSTALL] Installing %s via apt-get.' % toolname)
                if repo: self.__apt_add_repo(repo)
                self.__apt_install(pk)

    # ==================================================================================================================
    # LOCAL INSTALL
    # ==================================================================================================================
    def __is_tool_available(self, tool):
        """Return true if the tool is installed on the device."""
        cmd = '{which} {tool}'.format(which=Constants.DEVICE_TOOLS['WHICH'], tool=tool)
        out = self._device.remote_op.command_blocking(cmd, internal=True)
        return True if out else False

    def __install_local(self, toolname, tool):
        """Push the binary from the workstation to the device"""
        local, command = tool['LOCAL'], tool['COMMAND']
        name = Utils.extract_filename_from_path(command)
        if not self.__is_tool_available(name):
            self._device.printer.verbose('[INSTALL] Manually installing: %s' % toolname)
            src = local
            dst = os.path.join('/usr/bin/', name)
            self._device.push(src, dst)
            self._device.remote_op.chmod_x(dst)
        else:
            self._device.printer.debug('[INSTALL] Tool already available: %s' % toolname)

    # ==================================================================================================================
    # CHECKERS AND CONFIGURATORS
    # ==================================================================================================================
    def _check_prerequisites(self):
        """Check if the prerequisites have been satisfied"""
        for tool in Constants.DEVICE_SETUP['PREREQUISITES']:
            if not self.__is_tool_available(tool):
                self._device.printer.error('Prerequisite Not Found: %s ' % tool)
                self._device.printer.error('Please install the requirements listed in the README file')
                return False
        return True

    def _refresh_package_list(self):
        """Refresh the list of installed packages."""
        cmd = '{dpkg} --get-selections | grep -v "deinstall" | cut -f1'.format(dpkg=Constants.DEVICE_TOOLS['DPKG'])
        out = self._device.remote_op.command_blocking(cmd, internal=True)
        self._packagelist = map(string.strip, out)

    def _parse_cydia_list(self):
        """Retrieve the content of the cydia.list file."""
        self.__apt_update()
        cmd = 'cat {cydialist}'.format(cydialist=Constants.CYDIA_LIST)
        out = self._device.remote_op.command_blocking(cmd, internal=True)
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
            else:
                self._device.printer.debug('Installation method not provided for %s. Skipping' % toolname)
        except Exception as e:
            self._device.printer.warning('Error occurred during installation of tools: %s' % e.message.strip())
            self._device.printer.warning('Trying to continue anyway...')

    # ==================================================================================================================
    # EXPORTED METHOD
    # ==================================================================================================================
    def configure(self):
        """Configure device: check prerequisites and install missing tools."""
        # Check Prerequisites
        if not self._check_prerequisites():
            return False

        # Installing coreutils
        self.__apt_update()
        self._configure_tool('COREUTILS')

        # Refresh package list
        self._refresh_package_list()
        # Parse cydia.list
        self._parse_cydia_list()
        # Configure tools
        map(self._configure_tool, Constants.DEVICE_SETUP['TOOLS'])
        return True
