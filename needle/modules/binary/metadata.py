from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'App Metadata',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Display the app's metadata: UUID, app name/version, bundle name/ID, bundle/data/binary directory, "
                       "binary path/name, entitlements, URL handlers, architectures, platform/SDK/OS version, ATS settings,"
                       "app extensions",
        'options': (
        ),
    }

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.notify('{:<20}: {:<30}'.format('Name', self.APP_METADATA['name']))
        self.printer.notify('{:<20}: {:<30}'.format('Binary Name', self.APP_METADATA['binary_name']))
        self.printer.notify('{:<20}: {:<30}'.format('Bundle ID', self.APP_METADATA['bundle_id']))
        self.printer.notify('{:<20}: {:<30}'.format('UUID', self.APP_METADATA['uuid']))
        self.printer.notify('{:<20}: {:<30}'.format('App Version', self.APP_METADATA['app_version']))

        self.printer.notify('{:<20}: {:<30}'.format('Data Directory', self.APP_METADATA['data_directory']))
        self.printer.notify('{:<20}: {:<30}'.format('Bundle Directory', self.APP_METADATA['bundle_directory']))
        self.printer.notify('{:<20}: {:<30}'.format('Binary Directory', self.APP_METADATA['binary_directory']))
        self.printer.notify('{:<20}: {:<30}'.format('Binary Path', self.APP_METADATA['binary_path']))

        self.printer.notify('{:<20}: {:<30}'.format('Architectures', ', '.join(self.APP_METADATA['architectures'])))
        self.printer.notify('{:<20}: {:<30}'.format('Platform Version', self.APP_METADATA['platform_version']))
        self.printer.notify('{:<20}: {:<30}'.format('SDK Version', self.APP_METADATA['sdk_version']))
        self.printer.notify('{:<20}: {:<30}'.format('Minimum OS', self.APP_METADATA['minimum_os']))

        # Entitlements
        entitlements = self.APP_METADATA['entitlements']
        if entitlements:
            self.printer.notify('{:<20}'.format('Entitlements',))
            for k, v in entitlements.items():
                self.printer.notify('\t\t {:<40}: {:<20}'.format(k, v))
        else:
            self.printer.info('Entitlements not found')

        # URL Handlers
        handlers = self.APP_METADATA['url_handlers']
        if handlers:
            self.printer.notify('{:<20}'.format('URL Handlers',))
            for h in handlers:
                self.printer.notify('\t\t %s' % h)
        else:
            self.printer.info('URL Handlers not found')

        # Apple Transport Security Settings
        ats_settings = self.APP_METADATA['ats_settings']
        if ats_settings:
            self.printer.notify('{:<20}'.format('Apple Transport Security Settings',))
            for k, v in ats_settings.items():
                if "NSExceptionDomains" in k:
                    self.printer.notify('\t\t NSExceptionDomains')
                    vals = v.items()
                    for x, y in vals:
                        self.printer.notify('\t\t\t {:<40}: {:<20}'.format(x, y))
                else:
                    self.printer.notify('\t\t {:<40}: {:<20}'.format(k, v))
        else:
            self.printer.info('Apple Transport Security Settings not found')

        # App Extensions
        if self.APP_METADATA['extensions']:
            for app_extension in self.APP_METADATA['extensions']:
                self.printer.notify('{:<20}'.format('Application Extension:',))
                self.printer.notify('\t\t {:<40}: {:<20}'.format('Extension Name', app_extension['bundle_displayname']))
                self.printer.notify('\t\t {:<40}: {:<20}'.format('Bundle ID', app_extension['bundle_id']))
                self.printer.notify('\t\t {:<40}: {:<20}'.format('Bundle Executable', app_extension['bundle_exe']))
                self.printer.notify('\t\t {:<40}: {:<20}'.format('Bundle Package Type', app_extension['bundle_package_type']))

                extension_data = app_extension['extension_data']
                for k, v in extension_data.items():
                    if "NSExtensionAttributes" in k:
                        self.printer.notify('\t\t NSExtensionAttributes')
                        vals = v.items()
                        for x, y in vals:
                            if "NSExtensionActivationRule" in x:
                                try:
                                    rules = y.items()
                                except:
                                    rules = None
                                if rules:
                                    for q, w in rules:
                                        self.printer.notify('\t\t\t {:<40}: {:<20}'.format(q, w))
                                else:
                                    self.printer.notify('\t\t\t {:<40}: {:<20}'.format(x, y))
                    else:
                        self.printer.notify('\t\t {:<40}: {:<20}'.format(k, v))
        else:
            self.printer.info('No Application Extensions found')
