from core.framework.module import StaticModule
from core.utils.constants import Constants
from core.utils.utils import Utils
from core.utils.printer import Colors


class Module(StaticModule):
    meta = {
        'name': 'Code Checks',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': "Static analysis of the source code of the app. Aims to find usage of potentially insecure functions. "
                       "Can be applied to a whole folder or, if 'SECONDARY_FOLDER' is specified, only to the diff computed among 2 versions of the same codebase."
                       "The module is going to check for possible vulnerabilities in: "
                       "WebViews, HTTP Cache, SSL, Cookies, SQL, Keyboard cache, Backgrounding, Pasteboard, Credential storage, Data storage, IPC, XML, Format strings",
        'options': (
            ('primary_folder', '', True, 'Folder to analyze'),
            ('secondary_folder', '', False, 'If specified, compute the diff with PRIMARY_FOLDER, and apply the checks only to modified files'),
            ('output', True, False, 'Full path of the output file')
        ),
    }

    GREP_OPTS = '''-irn -H --include="*.m" --exclude-dir=.{git,hg,svn}'''
    AWK = '''| awk -F":" '{print $1}'| sort | uniq'''
    CHECKS = {
        'backgrounding':
            ['applicationWillResignActive', 'applicationWillTerminate', 'applicationDidEnterBackground'],
        'c_calls':
            ['strcat', 'strcpy', 'strncat', 'strncpy', 'sprintf', 'vsprintf', 'fopen', 'gets(', 'chmod', 'stat(', 'mktemp'],
        'cookies':
            ['NSHTTPCookieAcceptPolicyNever', 'NSHTTPCookieAcceptPolicyOnlyFromMainDocumentDomain'],
        'encoding':
            ['base64', 'MD5'],
        'files':
            ['NSFile', 'writeToFile'],
        'format_strings':
            ['''NSLog *([^\"']*)''', '''stringWithFormat[^\"']*(,|])''', '''initWithFormat[^\"']*(,|\])''',
             '''appendFormat[^\"']*(,|\])''', '''informativeTextWithFormat[^\"']*(,|\])''',
             '''predicateWithFormat[^\"']*(,|\])''', '''stringByAppendingFormat[^\"']*(,|\])''',
             '''alertWithMessageText[^\"']*(,|\])''', '''NSException +format[^\"']*(,|\])''', 'NSRunAlertPanel'],
        'handlers':
            ['://', 'openUrl', 'handleOpenURL'],
        'http':
            ['http://', 'NSURL', 'URL', 'writeToUrl', 'NSURLConnection', 'CFStream', 'NSStreamin'],
        'https_cacheing':
            ['willCacheResponse'],
        'keyboard_cache':
            ['autocorrectionType', 'UITextAutocorrectionNo'],
        'logging':
            ['NSLog'],
        'password_references':
            ['password'],
        'sql':
            ['SQL', 'sqlite', 'table', 'cursor', 'sqlite3_prepare(', 'sqlcipher'],
        'file_storage':
            ['NSUserDefaults', 'NSDataWritingFileProtectionNone', 'NSDataWritingFileProtectionComplete',
             'NSDataWritingFileProtectionCompleteUnlessOpen',
             'NSDataWritingFileProtectionCompleteUntilFirstUserAuthentication',
             'NSFileProtectionKey', 'NSFileProtectionNone', 'NSFileProtectionComplete',
             'NSFileProtectionCompleteUnlessOpen',
             'NSFileProtectionCompleteUntilFirstUserAuthentication'],
        'keychain_storage':
            ['SecItemAdd', 'SecItemUpdate', 'SecItemCopyMatching', 'kSecASttr', 'SFHFKkey'],
        'ssl':
            ['canAuthenticateAgainstProtectionSpace', 'setAllowsAnyHTTPSCertificate',
             'didReceiveAuthenticationChallenge', 'willSendRequestForAuthenticationChallenge',
             'continueWithoutCredentialForAuthenticationChallenge', 'kCFStreamSSLAllowsExpiredCertificates',
             'kCFStreamSSLAllowsExpiredRoots', 'kCFStreamSSLAllowsAnyRoot', 'kCFStreamSSLValidatesCertificateChain',
             'kCFStreamPropertySSLSettings', 'kCFStreamSSLPeerName', 'kSecTrustOptionAllowExpired',
             'kSecTrustOptionAllowExpiredRoot', 'kSecTrustOptionImplicitAnchors', 'NSStreamSocketSecurityLevelTLSv1',
             'NSStreamSocketSecurityLevelKey'],
        'pasteboard':
            ['UIPasteboardNameGeneral', 'UIPasteboardNameFind', 'pasteboardWithName', 'pasteboardWithUniqueName'],
        'webviews':
            ['UIWebView', 'loadRequest', 'loadHTMLString', 'shouldStartLoadWithRequest',
             'stringByEvaluatingJavaScriptFromString', 'baseURL'],
        'xml':
            ['foundExternalEntityDeclarationWithName', 'foundAttributeDeclarationWithName',
             'foundElementDeclarationWithName', 'foundInternalEntityDeclarationWithName',
             'foundUnparsedEntityDeclarationWithName', 'foundNotationDeclarationWithName'],
    }

    # ==================================================================================================================
    # INIT
    # ==================================================================================================================
    def __init__(self, params):
        StaticModule.__init__(self, params)
        # Instantiate vars
        self.diffs = None
        self.findings = {}
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("code_checks.txt", self)

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def _compute_diff(self):
        # Run diff
        cmd = "{bin} -qr {f1} {f2}".format(bin=Constants.PATH_TOOLS_LOCAL['DIFF'], f1=self.options['primary_folder'], f2=self.options['secondary_folder'])
        out, err = self.local_op.command_blocking(cmd)
        # Sort
        res = filter(None, out.split('\n'))
        modified = []
        for line in res:
            if 'differ' in line:
                modified.append(line.split()[-2])
            elif self.options['secondary_folder'] in line:
                temp = line[len("Only in "):]
                temp = temp.replace(": ", "/")
                modified.append(temp)
        return modified

    def _grep(self, what, awk=False):
        def do_grep(what, where, select):
            cmd = "{bin} {opts} {what} {where} {select}".format(bin=Constants.PATH_TOOLS_LOCAL['GREP'], opts=self.GREP_OPTS, what=what, where=where, select=select)
            out, err = self.local_op.command_blocking(cmd)
            return filter(None, out.split('\n'))

        # Filter with AWK
        select = self.AWK if awk else ""
        # Where to search for
        if self.diffs:
            to_check = []
            for d in self.diffs:
                where = Utils.escape_path(d)
                to_check.extend(do_grep(what, where, select))
            return to_check
        else:
            where = Utils.escape_path(self.options['primary_folder'])
            return do_grep(what, where, select)

    def _extract_lines(self, fnames, searchfor):
        found = []
        for name in fnames:
            try:
                with open(name, "rb") as fp:
                    for i, line in enumerate(fp):
                        line = line.strip()
                        if searchfor.lower() in line.lower():
                            found.append({'name': name, 'linenum': i+1, 'line': line})
            except:
                pass
        return found

    # ==================================================================================================================
    # MAIN FUNCTIONS
    # ==================================================================================================================
    def detect_type(self):
        if self.options['secondary_folder']:
            self.printer.info("Computing diff...")
            self.diffs = self._compute_diff()

    def execute_test(self, category, list_of_checks):
        def run_check(what):
            res = self._grep("'%s'" % what, awk=True)
            return self._extract_lines(res, searchfor=what)
        self.findings[category] = map(run_check, list_of_checks)

    def print_findings(self):
        file_output = []
        for category in self.findings:
            results = [item for sublist in self.findings[category] for item in sublist]
            if results:
                print("\n\n")
                header = "Check: %s" % category
                file_output.append(header)
                self.printer.notify(header)
                for r in results:
                    file_output.append('\t[{:<80}] line {:<5} -> {:<30}'.format(r['name'], r['linenum'], r['line']))
                    print('\t{}[{:<80}]{} line {:<5}{} -> {:<30}'.format(Colors.B, r['name'], Colors.O, r['linenum'], Colors.N, r['line']))

        # Save to file
        outfile = self.options['output'] if self.options['output'] else None
        self.print_cmd_output(file_output, outfile, silent=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Detect if the test needs to be run on a diff or on an entire folder
        self.detect_type()
        # Execute tests
        self.printer.info("Checking for insecure functions...")
        for category in self.CHECKS:
            self.execute_test(category, self.CHECKS[category])
        # Print findings
        self.print_findings()
