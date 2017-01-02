from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Checksums',
        'author': 'Henry Hoggard (@MWRLabs)',
        'description': 'Compute different checksums of the application binary: MD5, SHA1, SHA224, SHA256, SHA384, SHA512',
        'options': (
        ),
    }

    CHECKSUMS = [
        "md5sum",
        "sha1sum",
        "sha224sum",
        "sha256sum",
        "sha384sum",
        "sha512sum"
    ]
    RES = {}

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)

    def compute_checksum(self, kind):
        cmd = "{} {}".format(kind, self.path)
        out = self.device.remote_op.command_blocking(cmd)
        checksum = out[0].split(" ")[0]
        self.RES[kind] = checksum

    def print_checksums(self):
        self.printer.notify("The following checksums have been computed:")
        for k, v in self.RES.items():
            self.printer.notify("\t{:<20}: {:<30}".format(k, v))

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.path = self.APP_METADATA['binary_path']
        self.printer.info("Calculating checksums for: {path}".format(path=self.path))

        # Computing
        map(self.compute_checksum, self.CHECKSUMS)
        # Printing
        self.print_checksums()
