from core.framework.module import BaseModule
from core.utils.constants import Constants
import imp


class Module(BaseModule):
    meta = {
        'name': 'Delete Installed Certificate',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'Delete one (or more) certificates installed on device',
        'options': (
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
        self.db = self.local_op.build_temp_path_for_file("TrustStore.sqlite3", self)
        if not self.device.remote_op.file_exist(self.truststore_path):
            raise Exception("TrustStore file not found on device!")
        else:
            self.device.pull(self.truststore_path, self.db)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Pull TrustStore.sqlite3
        self.pull_ts()

        # Delete certificates
        adv = imp.load_source("TrustStore", self.TOOLS_LOCAL['ADVTRUSTSTORE'])
        tstore = adv.TrustStore(self.db)
        tstore.delete_certificates()

        # Backup
        self.printer.debug("Backing up the original TrustStore...")
        bkp = "%s.bkp" % Constants.DEVICE_PATH_TRUST_STORE
        self.device.remote_op.file_copy(self.truststore_path, bkp)

        # Updating device
        self.printer.info("Uploading new TrustStore to device...")
        self.device.push(self.db, self.truststore_path)
