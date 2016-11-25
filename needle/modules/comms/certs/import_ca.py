from core.framework.module import BaseModule
from core.utils.constants import Constants
import os
import imp


class Module(BaseModule):
    meta = {
        'name': 'Import Certificate',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Import a certificate from a file in PEM format',
        'options': (
            ('certificate', "", True, 'Full path to the PEM file'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    def pull_ts(self):
        self.printer.info("Looking for the TrustStore.sqlite3 file...")
        self.truststore_path = Constants.DEVICE_PATH_TRUST_STORE
        if not self.device.remote_op.file_exist(self.truststore_path):
            raise Exception("TrustStore file not found on device!")
        else:
            self.db = self.local_op.build_temp_path_for_file("TrustStore.sqlite3", self)
            self.device.pull(self.truststore_path, self.db)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Pull TrustStore.sqlite3
        self.pull_ts()

        # Load PEM file
        self.printer.info("Loading file: %s" % self.options['certificate'])
        adv = imp.load_source("TrustStore", self.TOOLS_LOCAL['ADVTRUSTSTORE'])
        cert = adv.Certificate()
        cert.load_PEMfile(self.options['certificate'])
        self.printer.notify("Loaded: %s" % cert.get_subject().strip())

        # Import certificates
        self.printer.info("Importing certificate...")
        tstore = adv.TrustStore(self.db)
        tstore.add_certificate(cert)

        # Backup
        self.printer.debug("Backing up the original TrustStore...")
        bkp = "%s.bkp" % Constants.DEVICE_PATH_TRUST_STORE
        self.device.remote_op.file_copy(self.truststore_path, bkp)

        # Updating device
        self.printer.info("Uploading new TrustStore to device...")
        self.device.push(self.db, self.truststore_path)
