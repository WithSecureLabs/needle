from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'App Metadata',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Display the app's metadata: UUID, app name/version, bundle name/ID, bundle/data/binary directory, "
                       "binary path/name, entitlements, URL handlers, architectures, platform/SDK/OS version",
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
