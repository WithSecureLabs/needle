from core.framework.module import BaseModule
from core.utils.constants import Constants
import imp


class Module(BaseModule):
    meta = {
        'name': 'List Installed Certificates',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'List the certificates installed on device',
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

        # List certificates
        adv = imp.load_source("TrustStore", self.TOOLS_LOCAL['ADVTRUSTSTORE'])
        tstore = adv.TrustStore(self.db)
        cert_list = tstore.list_certificates()

        # Print Certificates
        if cert_list:
            self.printer.notify("The following certificates are installed on the device:")
            for el in cert_list:
                self.printer.notify(el.get_subject().strip())
        else:
            self.printer.warning("No certificates found")
