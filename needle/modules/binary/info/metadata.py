from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'App Metadata',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Display the app's metadata: UUID, app name/version, bundle name/ID, bundle/data/binary directory, "
                       "binary path/name, signer identity, entitlements, URL handlers, architectures, platform/SDK/OS version, ATS settings,"
                       "app extensions",
        'options': (
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def _print_url_handlers(self, handlers, ident=0):
        tab_base = '\t' * ident
        tab_sub = tab_base + '\t' * 2
        if handlers:
            self.printer.notify('{}{:<20}'.format(tab_base, 'URL Handlers'))
            for h in handlers:
                self.printer.notify('{}{}'.format(tab_sub, h))
        else:
            self.printer.info('{}URL Handlers not found'.format(tab_base))

    def _print_ats(self, ats, ident=0):
        tab_base = '\t' * ident
        tab_sub = tab_base + '\t' * 2
        if ats:
            self.printer.notify('{}{:<20}'.format(tab_base, 'Apple Transport Security Settings'))
            for k, v in ats.items():
                if "NSAllowsArbitraryLoads" in k and v:
                    self.printer.error('{}{:<40}: {:<20}'.format(tab_sub, k, v))
                    self.add_issue('ATS Disabled', '{}: {}'.format(k, v), 'HIGH', None)
                elif "NSExceptionDomains" in k:
                    self.printer.notify('{}NSExceptionDomains'.format(tab_sub))
                    vals = v.items()
                    for x, y in vals:
                        self.printer.notify('{}{}{:<40}: {:<20}'.format(tab_sub, tab_sub, x, y))
                        self.add_issue('ATS disabled for some domains', '{}: {}'.format(x, y), 'HIGH', None)
                else:
                    self.printer.notify('{}{:<40}: {:<20}'.format(tab_sub, k, v))
        else:
            self.printer.info('{}Apple Transport Security Settings not found'.format(tab_base))

    def _print_entitlements(self, ents):
        if ents:
            self.printer.notify('{:<20}'.format('Entitlements',))
            for k, v in ents.items():
                if "get-task-allow" in k and v:
                    self.printer.error('\t\t{:<40}: {:<20}'.format(k, v))
                    self.add_issue('Debug allowed', '{}: {}'.format(k, v), 'HIGH', None)
                else:
                    self.printer.notify('\t\t {:<40}: {:<20}'.format(k, v))
        else:
            self.printer.info('Entitlements not found')

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Bundle
        self.printer.notify('{:<20}: {:<30}'.format('Name', self.APP_METADATA['name']))
        self.printer.notify('{:<20}: {:<30}'.format('Binary Name', self.APP_METADATA['binary_name']))
        self.printer.notify('{:<20}: {:<30}'.format('Bundle Executable', self.APP_METADATA['bundle_exe']))
        self.printer.notify('{:<20}: {:<30}'.format('Bundle ID', self.APP_METADATA['bundle_id']))
        self.printer.notify('{:<20}: {:<30}'.format('Bundle Type', self.APP_METADATA['bundle_type']))
        self.printer.notify('{:<20}: {:<30}'.format('UUID', self.APP_METADATA['uuid']))
        self.printer.notify('{:<20}: {:<30}'.format('Team ID', self.APP_METADATA['team_id']))
        self.printer.notify('{:<20}: {:<30}'.format('Signer Identity', self.APP_METADATA['signer_identity']))

        # Paths
        self.printer.notify('{:<20}: {:<30}'.format('Bundle Directory', self.APP_METADATA['bundle_directory']))
        self.printer.notify('{:<20}: {:<30}'.format('Binary Directory', self.APP_METADATA['binary_directory']))
        self.printer.notify('{:<20}: {:<30}'.format('Binary Path', self.APP_METADATA['binary_path']))
        self.printer.notify('{:<20}: {:<30}'.format('Data Directory', self.APP_METADATA['data_directory']))

        # Compilation
        self.printer.notify('{:<20}: {:<30}'.format('Bundle Package Type', self.APP_METADATA['bundle_package_type']))
        self.printer.notify('{:<20}: {:<30}'.format('App Version', self.APP_METADATA['app_version']))
        self.printer.notify('{:<20}: {:<30}'.format('Architectures', ', '.join(self.APP_METADATA['architectures'])))
        self.printer.notify('{:<20}: {:<30}'.format('Platform Version', self.APP_METADATA['platform_version']))
        self.printer.notify('{:<20}: {:<30}'.format('SDK Version', self.APP_METADATA['sdk_version']))
        self.printer.notify('{:<20}: {:<30}'.format('Minimum OS', self.APP_METADATA['minimum_os']))

        # URL Handlers
        self._print_url_handlers(self.APP_METADATA['url_handlers'], ident=0)

        # Apple Transport Security Settings
        self._print_ats(self.APP_METADATA['ats_settings'], ident=0)

        # Entitlements
        entitlements = self.APP_METADATA['entitlements']
        self._print_entitlements(entitlements)

        # App Extensions
        if self.APP_METADATA['extensions']:
            for app_extension in self.APP_METADATA['extensions']:
                print
                self.printer.notify('{:<20}'.format('Application Extension:',))

                self.printer.notify('\t\t{:<40}: {:<20}'.format('Bundle Display Name', app_extension['bundle_displayname']))
                self.printer.notify('\t\t{:<40}: {:<20}'.format('Bundle Executable', app_extension['bundle_exe']))
                self.printer.notify('\t\t{:<40}: {:<20}'.format('Bundle ID', app_extension['bundle_id']))
                self.printer.notify('\t\t{:<40}: {:<20}'.format('Bundle Version', app_extension['bundle_version']))
                self.printer.notify('\t\t{:<40}: {:<20}'.format('Bundle Package Type', app_extension['bundle_package_type']))
                self.printer.notify('\t\t{:<40}: {:<20}'.format('Platform Version', app_extension['platform_version']))
                self._print_url_handlers(app_extension['url_handlers'], ident=2)
                self._print_ats(self.APP_METADATA['ats_settings'], ident=2)

                extension_data = app_extension['extension_data']
                for k, v in extension_data.items():
                    self.printer.notify('\t\t{:<40}: {:<20}'.format(k, v))
        else:
            self.printer.info('No Application Extensions found')
