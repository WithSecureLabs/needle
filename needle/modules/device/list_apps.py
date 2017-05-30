from core.framework.module import BaseModule
from core.utils.menu import choose_from_list


class Module(BaseModule):
    meta = {
        'name': 'List Installed Applications',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Provide a list of the bundle IDs of all the apps installed on the device',
        'options': (
            ('hide_system_apps', False, True, 'If set to True, only 3rd party apps will be shown'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info('Looking for apps...')
        self.device._list_apps(self.options['hide_system_apps'])
        self.printer.notify('Apps found:')
        choose_from_list(self.device._applist.keys(), choose=False)
