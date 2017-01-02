from core.framework.module import BaseModule
from core.utils.menu import choose_boolean


class Module(BaseModule):
    meta = {
        'name': 'Theos Tweak',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Automate management of THEOS Tweaks. To see a full list of commands for this module, please refer to the "Comments" section.',
        'options': (
            ('project_name', "", True, 'Project name'),
            ('package_name', "", True, 'Package Name [yourcompany.test]. The "needle." prefix will be automatically added'),
            ('substrate_filter', "", False, 'MobileSubstrate Bundle filter [com.apple.springboard]'),
            ('terminate_app', "", False, "List of applications to terminate upon installation (space-separated) [SpringBoard]"),
            ('program', 'VIM', True, 'Select the program to use for editing files. Currently supported: VIM, NANO'),
        ),
        'comments': [
            'run: create, edit, and install Tweak',
            'view: view the Tweak',
            'edit: edit and reinstall the Tweak',
            'install: (re)install the Tweak',
            'disinstall: disinstall the Tweak',
            '(For further instructions, see: https://github.com/mwrlabs/needle/wiki/Theos-Integration)'
        ]
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        self.options['substrate_filter'] = self.APP_METADATA['bundle_id'] if self.APP_METADATA else ""
        # Ensure a valid editor has been specified
        self.validate_editor()

    def __init_const(self):
        # Parse options
        project_name = self.options['project_name'].lower()
        package_name = 'needle.{}'.format(self.options['package_name'])
        substrate_filter = self.options['substrate_filter'] if self.options['substrate_filter'] else ''
        terminate_app = self.options['terminate_app'] if self.options['terminate_app'] else '-'
        # Build paths
        self.project_folder = '{}{}'.format(self.device.TEMP_FOLDER, project_name)
        self.tweak = "{}/Tweak.xm".format(self.project_folder)
        # Build config list
        cfg = [
            '11',
            project_name,
            package_name,
            'Needle',
            substrate_filter,
            terminate_app,
        ]
        self.cfg = '\n'.join(cfg)

    def __bypass_wizard(self):
        bypass = False
        if self.device.remote_op.dir_exist(self.project_folder):
            msg = "A Tweak with the same PROJECT_NAME ({}) already exists. Do you want to delete it and start from scratch?".format(self.options['project_name'])
            clean = choose_boolean(msg)
            if clean:
                self.device.remote_op.dir_delete(self.project_folder)
            else:
                bypass = True
        return bypass

    def __wizard(self):
        if self.__bypass_wizard():
            self.printer.info('Bypassing wizard. Continuing with previous Tweak...')
            return
        self.printer.info("Starting wizard...")
        cmd = "cd {tmp} && printf {cfg_str} | {perl} {nic}".format(
            tmp=self.device.TEMP_FOLDER,
            cfg_str=repr(self.cfg),
            perl=self.device.DEVICE_TOOLS['PERL'],
            nic=self.device.DEVICE_TOOLS['THEOS_NIC'])
        self.device.remote_op.command_blocking(cmd)
        # Print content
        self.printer.info('Tweak created:')
        out = self.device.remote_op.dir_list(self.project_folder)
        self.print_cmd_output(out)

    # ==================================================================================================================
    #  MAIN ACTIONS
    # ==================================================================================================================
    def _tweak_view(self):
        self.printer.info("Content of the Tweak:")
        out = self.device.remote_op.read_file(self.tweak)
        self.print_cmd_output(out)

    def _tweak_edit(self):
        self.path_local = self.local_op.build_output_path_for_file("Tweak.xm", self)
        # Pull the file
        self.device.pull(self.tweak, self.path_local)
        # Modify it in the selected editor
        cmd = '{editor} {fname}'.format(editor=self.editor, fname=self.path_local)
        self.local_op.command_interactive(cmd)
        # Updating device
        self.printer.info("Uploading new Tweak to device...")
        self.device.push(self.path_local, self.tweak)

    def _tweak_install(self):
        self.printer.info("Installing the Tweak...")
        cmd = "export THEOS=/private/var/theos && export PATH=$THEOS/bin:$PATH && cd {proj} && make package install".format(proj=self.project_folder)
        self.device.remote_op.command_interactive_tty(cmd)

    def _tweak_disinstall(self):
        self.printer.info("Disinstalling the Tweak...")
        cmd = "{dpkg} -r {package}".format(dpkg=self.device.DEVICE_TOOLS['DPKG'], package=self.options['package_name'])
        out = self.device.remote_op.command_blocking(cmd)
        self.print_cmd_output(out)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Init const
        self.__init_const()
        # Starting wizard
        self.__wizard()
        # Edit Tweak
        self._tweak_edit()
        # Install Tweak
        self._tweak_install()

    def do_view(self, params):
        def view():
            self.__init_const()
            self._tweak_view()
        self.do_run(params, func=view)

    def do_edit(self, params):
        def edit():
            self.__init_const()
            self._tweak_edit()
            self._tweak_install()
        self.do_run(params, func=edit)

    def do_install(self, params):
        def install():
            self.__init_const()
            self._tweak_install()
        self.do_run(params, func=install)

    def do_disinstall(self, params):
        def disinstall():
            self.__init_const()
            self._tweak_disinstall()
        self.do_run(params, func=disinstall)
