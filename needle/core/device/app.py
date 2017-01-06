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
        plist_mobile_installation = self._device._applist[self._app]
        metadata_mobile_installation = self.__parse_plist_mobile_installation(plist_mobile_installation)

        # Content of the app's local Info.plist
        plist_info_path = Utils.escape_path('%s/Info.plist' % plist_mobile_installation['Path'])
        plist_info = self._device.remote_op.parse_plist(plist_info_path)
        metadata_info = self.__parse_plist_info(plist_info)

        # Compose binary path
        binary_directory = metadata_mobile_installation['binary_directory']
        binary_name = metadata_info['bundle_exe']
        binary_path = Utils.escape_path(os.path.join(binary_directory, binary_name))

        # Detect architectures
        architectures = self.__detect_architectures(binary_path)

        # App Extensions
        extensions = self.get_extensions(binary_directory)

        # Pack into a dict
        metadata = {
            'binary_path': binary_path,
            'binary_name': binary_name,
            'architectures': architectures,
            'extensions': extensions,
        }
        metadata = Utils.merge_dicts(metadata, metadata_mobile_installation, metadata_info)
        return metadata

    def __parse_plist_mobile_installation(self, plist):
        # Parse the MobileInstallation plist
        uuid = self.__extract_field(plist, 'BundleContainer').rsplit('/', 1)[-1]
        name = self.__extract_field(plist, 'Path').rsplit('/', 1)[-1]
        bundle_id = self.__extract_field(plist, 'CFBundleIdentifier')
        bundle_directory = self.__extract_field(plist, 'BundleContainer')
        data_directory = self.__extract_field(plist, 'Container')
        binary_directory = self.__extract_field(plist, 'Path')
        entitlements = self.__extract_field(plist, 'Entitlements')
        # Pack into a dict
        metadata = {
            'uuid': uuid,
            'name': name,
            'bundle_id': bundle_id,
            'bundle_directory': bundle_directory,
            'data_directory': data_directory,
            'binary_directory': binary_directory,
            'entitlements': entitlements,
        }
        return metadata

    def __parse_plist_info(self, plist):
        # Parse the Info.plist file
        sdk_version = self.__extract_field(plist, 'DTSDKName')
        minimum_os = self.__extract_field(plist, 'MinimumOSVersion')
        bundle_id = self.__extract_field(plist, 'CFBundleIdentifier')
        bundle_displayname = self.__extract_field(plist, 'CFBundleDisplayName')
        bundle_exe = self.__extract_field(plist, 'CFBundleExecutable')
        bundle_package_type = self.__extract_field(plist, 'CFBundlePackageType')
        app_version_long = self.__extract_field(plist, 'CFBundleVersion')
        app_version_short = self.__extract_field(plist, 'CFBundleShortVersionString')
        app_version = '{} ({})'.format(app_version_long, app_version_short)
        platform_version = self.__extract_field(plist, 'DTPlatformVersion')
        ats_settings = self.__extract_field(plist, 'NSAppTransportSecurity')
        try:
            url_handlers = [url['CFBundleURLSchemes'] for url in plist['CFBundleURLTypes']]
        except:
            url_handlers = None
        # Pack into a dict
        metadata = {
            'platform_version': platform_version,
            'sdk_version': sdk_version,
            'minimum_os': minimum_os,
            'bundle_id': bundle_id,
            'bundle_displayname': bundle_displayname,
            'bundle_exe': bundle_exe,
            'bundle_package_type': bundle_package_type,
            'app_version': app_version,
            'url_handlers': url_handlers,
            'ats_settings': ats_settings,
        }
        return metadata

    def __extract_field(self, plist, field):
        """Extract the specified entry from the plist file. Returns empty string if not present."""
        try:
            return plist[field]
        except:
            return ""

    def __detect_architectures(self, binary):
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
            self._device.printer.verbose("No Plugins found")
            return None

    def _retrieve_extensions(self, plugin_dir):
        # Find plugins
        file_list = self._device.remote_op.dir_list(plugin_dir)
        appex = filter(lambda x: "appex" in x, file_list)
        plugins = [os.path.join(plugin_dir, x) for x in appex]

        # Parse the plist for each extension found
        extensions = []
        for plugin in plugins:
            plist_path = os.path.join(plugin, "Info.plist")
            plist_info = self._device.remote_op.parse_plist(plist_path)
            metadata_info = self.__parse_plist_info(plist_info)
            extension_data = plist_info['NSExtension']
            # Build the dict
            extension_metadata = {
                'extension_data': extension_data,
            }
            extension_metadata = Utils.merge_dicts(metadata_info, extension_metadata)
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
                msg = 'marked as executable (using chmod +x /usr/bin/Clutch* from a device shell)'
            elif 'Clutch2: command not found' in out[0]:
                msg = 'installed on the device (by running again with SETUP_DEVICE=True)'

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

        # Unzip IPA and get binary path
        fname_binary = self.unpack_ipa(app_metadata, fname_decrypted)
        return fname_binary

    # ==================================================================================================================
    # UNPACK AN IPA FILE
    # ==================================================================================================================
    def unpack_ipa(self, app_metadata, ipa_fname):
        # Leftovers Cleanup
        payload_folder = '%s%s' % (self._device.TEMP_FOLDER, 'Payload')
        itunes = '%s%s' % (self._device.TEMP_FOLDER, 'iTunesArtwork')
        if self._device.remote_op.dir_exist(payload_folder): self._device.remote_op.dir_delete(payload_folder)
        if self._device.remote_op.file_exist(itunes): self._device.remote_op.file_delete(itunes)

        # Unzip
        self._device.printer.info("Unpacking the IPA...")
        cmd = '{bin} {ipa} -d {folder}'.format(bin=self._device.DEVICE_TOOLS['UNZIP'],
                                               ipa=ipa_fname,
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
        shortname = stripped.replace(app_metadata['bundle_directory'], 'bundledir')
        shortname = shortname.replace(app_metadata['data_directory'], 'datadir')

        # Remove extraneous ' symbols
        shortname = shortname.replace('\'', '')
        # Convert the directory path to a simple filename: swap the / symbol for a _ symbol
        shortname = shortname.replace('/', '_')
        # Remove spaces
        shortname = shortname.replace(' ', '')
        return shortname
