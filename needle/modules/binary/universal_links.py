
from core.framework.module import BaseModule

import urllib2
import urlparse
import ssl
import os

class Module(BaseModule):
    meta = {
        'name': 'Universal Links',
        'author': '@alexjplaskett (@MWRLabs)',
        'description': "Display an applications universal links. (>iOS 9). "
        "Can also determine if apple-app-site-association is signed or not.",
        'options': (
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)

    def is_data_signed(self,data):
        """Determine if the file looks like its signed and should be verififed """
        if data[0] == "\x30" and data[1] == "\x82":
            return True
        else:
            return False

    def verify_signature(self,data,verify=True):
        """Verify the SMIME signature on the file"""
        temp_assoc_fn = os.path.join(self.path_home_temp,"assoc-temp")

        fd = open(temp_assoc_fn,"w")
        fd.write(data)
        fd.close()

        # Now we try verify the SMIME signature using built in CAs (unless verify is set to false)
        if verify:
            cmd = '{app} smime -verify -in {path} -inform DER -purpose sslserver'.format(app=self.TOOLS_LOCAL['OPENSSL'],path=temp_assoc_fn)
        else:
            cmd = '{app} smime -verify -noverify -in {path} -inform DER -purpose sslserver'.format(app=self.TOOLS_LOCAL['OPENSSL'],path=temp_assoc_fn)

        data = self.local_op.command_blocking(cmd)
        stdout = data[0]
        stderr = data[1]

        # Remove the temp file
        try:
            os.remove(temp_assoc_fn)
        except:
            self.printer.debug("Could not remove the local temp apple-app-site-association file.")

        return (stdout,stderr)

    def can_open_url(self,url):
        """ Determine if we can open the URL to the apple-app-site-association """
        try:
            response = urllib2.urlopen(url)
            return response
        except urllib2.HTTPError, e:
            self.printer.info("Failed with error code: %s" % e.code)
            return None 

    def get_site_associations(self,domain):
        """ Construct the path to the apple-app-site-association file. """
        fn = "apple-app-site-association"

        # First try https in the root of the webserver.
        if not "https" in domain:
            url = "https://" + domain
        else:
            url = domain 

        url = urlparse.urljoin(url,fn)

        self.printer.info("Using url: %s" % url)

        response = self.can_open_url(url)

        if not response:
            url = urlparse.urljoin(url,".well-known",fn)
            response = self.can_open_url(url)
            # Fall back to HTTP
            if not response:
                url = "http://" + domain 
                response = self.can_open_url(url)
                if not response:
                    url = urlparse.urljoin(url,".well-known",fn)
                    response = self.can_open_url(url)

        if response:
            try:
                data = response.read()
            except:
                data = None 
        else:
            self.printer.info("Could not retreive apple-app-site-association")
        
        if not data:
            self.printer.info("Could not get data from URL")
        else:
            self.printer.info("Got apple-app-site-association data from URL")

            if self.is_data_signed(data):
                self.printer.info("Data is signed")
                # Check if the signature is valid
                verified = False 
                output = self.verify_signature(data)

                if "Verification successful" in output[1]:
                    self.printer.info("Signature validation successful")
                    verified = True
                else:
                    self.printer.info("Signature validation failed")
                    output = self.verify_signature(data,verify=False)

                json = output[0]

                if json:
                    self.printer.info(json)

            else:
                self.printer.info("Data is not signed!")
                self.printer.info(data)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Dumping universal links used by application..")

        # First check if the application has the universal links entitlement. 
        entitlements = self.APP_METADATA['entitlements']

        associated_domains = []

        if entitlements:
        	for k, v in entitlements.items():
        		if "com.apple.developer.associated-domains" in k:
        			for domain in v:
        				associated_domains.append(domain)
        else:
            self.printer.info('com.apple.developer.associated-domains entitlement not found')
            return 

        # If it has then determine if there are universal links setup on the domain. 
        if associated_domains:
            self.printer.notify('{:<20}'.format('Associated Domains',))
            for domain in associated_domains:
                if "applinks" in domain:
                    domain = domain.split("applinks:")[1]   
                    self.printer.info(domain)
                    self.get_site_associations(domain)
                elif "webcredentials" in domain:
                    pass

