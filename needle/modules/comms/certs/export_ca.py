from core.framework.module import BaseModule
from core.utils.constants import Constants
import os
import imp


class Module(BaseModule):
    meta = {
        'name': 'Export Installed Certificate',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Export one (or more) certificates installed on device',
        'options': (
            ('output', "", True, 'Full path of the folder where to save the exported certificates'),
            ('fulldata', False, True, 'Set to True to export data, sha1, subject in separate files (when set to False, only the public key will be exported).'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("certs", self)

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    def pull_ts(self):
        self.printer.info("Looking for the TrustStore.sqlite3 file...")
        self.truststore_path = Constants.DEVICE_PATH_TRUST_STORE
        if not self.device.remote_op.file_exist(self.truststore_path):
            raise Exception("TrustStore file not found on device!")
        else:
            self.db = self.local_op.build_output_path_for_file("TrustStore.sqlite3", self)
            self.device.pull(self.truststore_path, self.db)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Pull TrustStore.sqlite3
        self.pull_ts()

        # Setup folders
        folder_out = self.options['output']
        if not self.local_op.dir_exist(folder_out): self.local_op.dir_create(folder_out)
        certificate_base_filename = os.path.join(folder_out, 'cert_')
        certificate_data_base_filename = os.path.join(folder_out, 'cert_data_')

        # Export certificates
        self.printer.info("Loading certificates...")
        adv = imp.load_source("TrustStore", self.TOOLS_LOCAL['ADVTRUSTSTORE'])
        tstore = adv.TrustStore(self.db)
        tstore.export_certificates(certificate_base_filename)
        if self.options['fulldata']:
            tstore.export_certificates_data(certificate_data_base_filename)
        self.printer.notify("Certificates exported in: %s" % folder_out)
