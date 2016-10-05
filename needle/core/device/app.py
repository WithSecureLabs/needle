import os

from ..utils.constants import Constants
from ..utils.utils import Utils


class App(object):
    def __init__(self, device):
        self._device = device
        self._app = None

    # ==================================================================================================================
    # METADATA
    # ==================================================================================================================
    def get_metadata(self, app_name):
        """Retrieve metadata of the target app."""
        self._app = app_name
        if self._device._applist is None:
            self._device._list_apps()
        return self._retrieve_metadata()

    def _retrieve_metadata(self):
        """Parse MobileInstallation.plist and the app's local Info.plist, and extract metadata."""
        # Content of the MobileInstallation plist
        plist_global = self._device._applist[self._app]
        uuid = plist_global['BundleContainer'].rsplit('/', 1)[-1]
        name = plist_global['Path'].rsplit('/', 1)[-1]
        bundle_id = plist_global['CFBundleIdentifier']
        bundle_directory = plist_global['BundleContainer']
        data_directory = plist_global['Container']
        binary_directory = plist_global['Path']
        try:
            entitlements = plist_global['Entitlements']
        except:
            entitlements = None

        # Content of the app's local Info.plist
        path_local = Utils.escape_path('%s/Info.plist' % plist_global['Path'])
        plist_local = self._device.remote_op.parse_plist(path_local)
        try:
            platform_version = plist_local['DTPlatformVersion']
        except:
            platform_version = None

        sdk_version = plist_local['DTSDKName']
        minimum_os = plist_local['MinimumOSVersion']
        app_version_long  = plist_local['CFBundleVersion']
        app_version_short = plist_local['CFBundleShortVersionString']
        app_version = '{} ({})'.format(app_version_long, app_version_short)
        try:
            url_handlers = plist_local['CFBundleURLTypes'][0]['CFBundleURLSchemes']
        except:
            url_handlers = None
        try:
            ats_settings = plist_local['NSAppTransportSecurity']
        except:
            ats_settings = None 

        # Compose binary path
        binary_folder = binary_directory
        binary_name = os.path.splitext(binary_folder.rsplit('/', 1)[-1])[0]
        binary_path = Utils.escape_path(os.path.join(binary_folder, binary_name))

        # Detect architectures
        architectures = self._detect_architectures(binary_path)

        # App Extensions
        extensions = self.get_extensions(binary_directory)

        # Pack into a dict
        metadata = {
            'uuid': uuid,
            'name': name,
            'app_version': app_version,
            'bundle_id': bundle_id,
            'bundle_directory': bundle_directory,
            'data_directory': data_directory,
            'binary_directory': binary_directory,
            'binary_path': binary_path,
            'binary_name': binary_name,
            'entitlements': entitlements,
            'platform_version': platform_version,
            'sdk_version': sdk_version,
            'minimum_os': minimum_os,
            'url_handlers': url_handlers,
            'ats_settings': ats_settings,
            'architectures': architectures,
            'extensions': extensions,
        }
        return metadata

    def _detect_architectures(self, binary):
        """Use lipo to detect supported architectures."""
        # Run lipo
        cmd = '{lipo} -info {binary}'.format(lipo=Constants.DEVICE_TOOLS['LIPO'], binary=binary)
        out = self._device.remote_op.command_blocking(cmd, internal=True)
        # Parse output
        msg = out[0].strip()
        res = msg.rsplit(': ')[-1].split(' ')
        return res

    # ==================================================================================================================
    # EXTENSION SUPPORT
    # ==================================================================================================================
    def get_extensions(self, binary_directory):
        """ Obtain the metadata for each extension."""
        plugin_dir = os.path.join(binary_directory, "PlugIns")
        if self._device.remote_op.dir_exist(plugin_dir):
            return self._retrieve_extensions(plugin_dir)
        else:
            return None

    def _retrieve_extensions(self, plugin_dir):
        # Find plugins
        items = self._device.remote_op.dir_list(plugin_dir)
        plugins = []
        for i in items:
            if "appex" in i:
                fn = str(i).strip()
                plugin_path = os.path.join(plugin_dir, fn)
                if self._device.remote_op.dir_exist(plugin_path):
                    plugins.append(plugin_path)

        # Parse the plist for each extension found
        extensions = []
        for plugin in plugins:
            plist_path = os.path.join(plugin, "Info.plist")
            plist_local = self._device.remote_op.parse_plist(plist_path)
            # Parse the plist
            bundle_id = plist_local['CFBundleIdentifier']
            bundle_displayname = plist_local['CFBundleDisplayName']
            bundle_exe = plist_local['CFBundleExecutable']
            bundle_package_type = plist_local['CFBundlePackageType']
            sdk_version = plist_local['DTSDKName']
            minimum_os = plist_local['MinimumOSVersion']
            extension_data = plist_local['NSExtension']
            try:
                platform_version = plist_local['DTPlatformVersion']
            except:
                platform_version = None

            # Build the dict
            extension_metadata = {
                'bundle_id': bundle_id,
                'bundle_displayname': bundle_displayname,
                'bundle_exe': bundle_exe,
                'bundle_package_type': bundle_package_type,
                'sdk_version': sdk_version,
                'platform_version': platform_version,
                'minimum_os': minimum_os,
                'extension_data': extension_data
            }
            extensions.append(extension_metadata)
        return extensions

    # ==================================================================================================================
    # MANIPULATE APP
    # ==================================================================================================================
    def open(self, bundle_id):
        """Launch the app with the specified Bundle ID."""
        cmd = '{open} {app}'.format(open=self._device.DEVICE_TOOLS['OPEN'], app=bundle_id)
        self._device.remote_op.command_blocking(cmd, internal=True)

    def search_pid(self, appname):
        """Retrieve the PID of the app's process."""
        self._device.printer.verbose('Retrieving the PID...')
        cmd = "ps ax | grep -i '{appname}'".format(appname=appname)
        out = self._device.remote_op.command_blocking(cmd)
        try:
            process_list = filter(lambda x: '/var/mobile' in x, out)
            if not process_list:
                process_list = filter(lambda x: '/var/containers' in x, out)
            process = process_list[0].strip()
            pid = process.split(' ')[0]
            self._device.printer.verbose('PID found: %s' % pid)
            return pid
        except Exception as e:
            raise Exception("PID not found")

    def decrypt(self, app_metadata):
        """Decrypt the binary and unzip the IPA. Returns the full path of the decrypted binary"""
        # Run Clutch
        self._device.printer.info("Decrypting the binary...")
        cmd = '{bin} -d {bundle} 2>&1'.format(bin=self._device.DEVICE_TOOLS['CLUTCH'], bundle=app_metadata['bundle_id'])
        out = self._device.remote_op.command_blocking(cmd)

        # Check if the app has been found
        fname_decrypted = self._device.remote_op.build_temp_path_for_file('decrypted.ipa')
        try:
            # Parse the output filename
            res = filter(lambda x: x.startswith('DONE'), out)
            out_temp = res[0].split(':')[1].strip()            # 'DONE: /private/var/mobile/Documents/Dumped/uid.ipa'
            # Move IPA to TEMP folder
            self._device.remote_op.file_copy(out_temp, fname_decrypted)
            # Remove temp IPA
            self._device.remote_op.file_delete(out_temp)
        except Exception:
            # Check if Clutch failed somehow
            msg = None
            if 'Clutch2: Permission denied' in out[0]:
                msg = 'marked as executable'
            elif 'Clutch2: command not found' in out[0]:
                msg = 'installed on the device'

            if msg:
                self._device.printer.error('Clutch2 could not be run successfully so the binary could not be decrypted')
                raise Exception('Please confirm that Clutch2 is {}'.format(msg))
            else:
                self._device.printer.warning('The app might be already decrypted. Trying to retrieve the IPA...')

            # Retrieving the IPA
            cmd = '{bin} -b {bundle} -o {out}'.format(bin=self._device.DEVICE_TOOLS['IPAINSTALLER'],
                                                      bundle=app_metadata['bundle_id'],
                                                      out=fname_decrypted)
            out = self._device.remote_op.command_blocking(cmd)
        self._device.printer.verbose("Decrypted IPA stored at: %s" % fname_decrypted)

        # Leftovers Cleanup
        payload_folder = '%s%s' % (self._device.TEMP_FOLDER, 'Payload')
        itunes = '%s%s' % (self._device.TEMP_FOLDER, 'iTunesArtwork')
        if self._device.remote_op.dir_exist(payload_folder): self._device.remote_op.dir_delete(payload_folder)
        if self._device.remote_op.file_exist(itunes): self._device.remote_op.file_delete(itunes)

        # Unzip
        self._device.printer.info("Unpacking the decrypted IPA...")
        cmd = '{bin} {ipa} -d {folder}'.format(bin=self._device.DEVICE_TOOLS['UNZIP'],
                                               ipa=fname_decrypted,
                                               folder=self._device.TEMP_FOLDER)
        out = self._device.remote_op.command_blocking(cmd)

        # Get full path to the binary
        cmd = '{find} {folder} -type f -name "{appname}"'.format(find=self._device.DEVICE_TOOLS['FIND'],
                                                                 folder=self._device.TEMP_FOLDER,
                                                                 appname=app_metadata['binary_name'])
        out = self._device.remote_op.command_blocking(cmd)
        fname_binary = out[0].strip()
        self._device.printer.debug("Full path of the application binary: %s" % fname_binary)
        return fname_binary

    # ==================================================================================================================
    # MANIPULATE FILES
    # ==================================================================================================================
    def get_dataprotection(self, filelist):
        """Get the Data Protection of the files contained in 'filelist'."""
        computed = []
        for el in filelist:
            fname = Utils.escape_path(el.strip())
            dp = '{bin} -f {fname}'.format(bin=self._device.DEVICE_TOOLS['FILEDP'], fname=fname)
            dp += ' 2>&1'                                            # needed because by default FileDP prints to STDERR
            res = self._device.remote_op.command_blocking(dp, internal=True)
            # Parse class
            cl = res[0].rsplit(None, 1)[-1]
            computed.append((fname, cl))
        return computed

    def convert_path_to_filename(self, fname, app_metadata):
        """Convert a path to a file name, stripping the path of the bundle/data."""
        # Path manipulation
        stripped = fname.strip()

        # Remove bundle/data path from the file name
        shortname = stripped.replace(app_metadata['bundle_directory'], '')
        shortname = shortname.replace(app_metadata['data_directory'], '')

        # Remove extraneous ' symbols
        shortname = shortname.replace('\'', '')
        # Convert the directory path to a simple filename: swap the / symbol for a _ symbol
        shortname.replace('/', '_')
        # Remove spaces
        shortname.replace(' ', '')
