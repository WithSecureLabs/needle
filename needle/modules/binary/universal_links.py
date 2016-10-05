from core.framework.module import BaseModule
import urllib2
import urlparse


class Module(BaseModule):
    meta = {
        'name': 'Universal Links',
        'author': '@alexjplaskett (@MWRLabs)',
        'description': "Display an applications universal links. Can also determine if apple-app-site-association is signed or not.",
        'options': (
            ('output', True, False, 'Full path of the output folder'),
        ),
        'comments': [
            'Only for iOS >= 9',
            'More info: https://developer.apple.com/library/content/documentation/General/Conceptual/AppSearch/UniversalLinks.html'
        ]
    }

    APPLE_APP_SITE_ASSOCIATION = 'apple-app-site-association'

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']

    def can_open_url(self, url):
        """Determine if it is possible to open the URL to the apple-app-site-association."""
        try:
            response = urllib2.urlopen(url)
            return response
        except urllib2.HTTPError as e:
            return None

    def _retrieve_apple_app_site_association(self, domain):
        # Construct the path to the apple-app-site-association file
        url_https = urlparse.urljoin("https://{}".format(domain), self.APPLE_APP_SITE_ASSOCIATION)
        url_https_known = urlparse.urljoin(url_https, ".well-known", self.APPLE_APP_SITE_ASSOCIATION)
        url_http = urlparse.urljoin("http://{}".format(domain), self.APPLE_APP_SITE_ASSOCIATION)
        url_http_known = urlparse.urljoin(url_http, ".well-known", self.APPLE_APP_SITE_ASSOCIATION)
        # First, try https in the root of the webserver
        self.printer.debug("\t\tTrying URL: {}".format(url_https))
        response = self.can_open_url(url_https_known)
        if not response:
            self.printer.debug("\t\t...Failed. Trying URL: {}".format(url_https_known))
            response = self.can_open_url(url_https_known)
            # Fall back to HTTP
            if not response:
                self.printer.debug("\t\t... Failed. Trying URL: {}".format(url_http))
                response = self.can_open_url(url_http)
                if not response:
                    self.printer.debug("\t\t... Failed. Trying URL: {}".format(url_http_known))
                    response = self.can_open_url(url_http_known)
        return response

    def is_data_signed(self,data):
        """Determine if the file looks like its signed and should be verified."""
        if data[0] == "\x30" and data[1] == "\x82":
            return True
        else:
            return False

    def verify_signature(self, data, verify=True):
        """Verify the SMIME signature of the file."""
        # Temporarily write the content on disk
        temp_assoc = self.local_op.build_temp_path_for_file(self, "assoc")
        self.local_op.write_file(temp_assoc, data)
        # Verify the SMIME signature using built-in CAs (unless verify is set to false)
        if verify:
            cmd = '{app} smime -verify -in {path} -inform DER -purpose sslserver'.format(app=self.TOOLS_LOCAL['OPENSSL'],
                                                                                         path=temp_assoc)
        else:
            cmd = '{app} smime -verify -noverify -in {path} -inform DER -purpose sslserver'.format(app=self.TOOLS_LOCAL['OPENSSL'],
                                                                                                   path=temp_assoc)

        out, err = self.local_op.command_blocking(cmd)
        return out, err

    def get_site_associations(self, domain):
        # Retrieve apple-app-site-association
        response = self._retrieve_apple_app_site_association(domain)

        # We have a hit
        if response:
            data = response.read()
            self.printer.debug("\t\tGot apple-app-site-association data")
            # Check signature
            if self.is_data_signed(data):
                #self.printer.debug('Data is signed')
                signed = True
                # Check if the signature is valid
                out, err = self.verify_signature(data)
                if "Verification successful" in err:
                    #self.printer.debug('Signature validation successful')
                    signature = True
                else:
                    #self.printer.debug('Signature validation failed')
                    signature = False
                    out, err = self.verify_signature(data, verify=False)
                data = out
            else:
                #self.printer.debug('Data is not signed')
                signed = False
                signature = None
            # Print & Save to file
            assoc_path = self.local_op.build_output_path_for_file(self, 'appsiteassoc_{}'.format(domain))
            outfile = str(assoc_path) if self.options['output'] else None
            self.print_cmd_output(data, outfile, silent=True)
        else:
            # Association not found
            self.printer.error("\t\tCould not retreive apple-app-site-association")
            signed, signature, outfile = None, None, None

        # Save result
        temp = [domain, signed, signature, outfile]
        self.association_results.append(temp)

    def print_results(self):
        self.printer.notify('The following apple-app-site-association has been found:')
        header = ['Domain', 'Data is Signed', 'Signature validation successful', 'Content']
        self.print_table(self.association_results, header=header)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Dumping universal links used by application...")

        # Reset output
        self.association_results = []

        # First check if the application has the universal links entitlement
        associated_domains = []
        entitlements = self.APP_METADATA['entitlements']
        if entitlements and ('com.apple.developer.associated-domains' in entitlements):
            for domain in entitlements['com.apple.developer.associated-domains']:
                associated_domains.append(domain)
        else:
            self.printer.error('"com.apple.developer.associated-domains" entitlement not found')
            return

        # Determine if there are universal links setup on the domain
        if associated_domains:
            for domain in associated_domains:
                if "applinks" in domain:
                    domain = domain.split("applinks:")[1]
                    self.printer.info('{:<20} {}'.format('Associated Domain found:', domain))
                    self.get_site_associations(domain)

        # Print results
        self.print_results()
