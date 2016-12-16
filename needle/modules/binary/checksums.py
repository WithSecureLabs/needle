from core.framework.module import BaseModule
import os

class Module(BaseModule):
    meta = {
        'name': 'Checksums',
        'author': 'Henry Hoggard (@MWRLabs)',
        'description': 'Returns MD5, SHA1, SHA224, SHA256, SHA384, SHA512 checksums for application binary',
        'options': (
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Any other customization goes here

        # Setting default output file
        # self.options['output'] = self.local_op.build_output_path_for_file("template.txt", self)

    def get_checksum(self, output):
        checksum = output[0].split(" ")
        return checksum[0]

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    

    def module_run(self):
        path = self.APP_METADATA['binary_path']
        self.printer.info("Calculating checksums for {path}".format(path=path))

        md5 = "md5sum {path}".format(path=path)
        sha1 = "sha1sum {path}".format(path=path)
        sha224 = "sha224sum {path}".format(path=path)
        sha256 = "sha256sum {path}".format(path=path)
        sha384 = "sha384sum {path}".format(path=path)
        sha512 = "sha512sum {path}".format(path=path)

        md5sum = self.get_checksum(self.device.remote_op.command_blocking(md5))
        sha1sum = self.get_checksum(self.device.remote_op.command_blocking(sha1))
        sha224sum = self.get_checksum(self.device.remote_op.command_blocking(sha224))
        sha256sum = self.get_checksum(self.device.remote_op.command_blocking(sha256))
        sha384sum = self.get_checksum(self.device.remote_op.command_blocking(sha384))
        sha512sum = self.get_checksum(self.device.remote_op.command_blocking(sha512))


        self.printer.notify("{:<20}:{:<30}".format("MD5Sum",md5sum))
        self.printer.notify("{:<20}:{:<30}".format("SHA1Sum",sha1sum))
        self.printer.notify("{:<20}:{:<30}".format("SHA224Sum",sha224sum))
        self.printer.notify("{:<20}:{:<30}".format("SHA256Sum",sha256sum))
        self.printer.notify("{:<20}:{:<30}".format("SHA384Sum",sha384sum))
        self.printer.notify("{:<20}:{:<30}".format("SHA512Sum",sha512sum))
