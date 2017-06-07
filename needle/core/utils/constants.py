import os
import sys

from ..utils.printer import Colors


class Constants(object):
    # ==================================================================================================================
    # METADATA
    # ==================================================================================================================
    # AUTHOR
    AUTHOR = 'MWR InfoSecurity (@MWRLabs) - Marco Lancini (@LanciniMarco)'
    EMAIL = 'marco.lancini[at]mwrinfosecurity.com'
    WEBSITE = 'mwr.to/needle'
    VERSION = '1.3.0'
    VERSION_CHECK = 'https://raw.githubusercontent.com/mwrlabs/needle/master/needle/core/utils/constants.py'

    # Name variables
    NAME = 'Needle'
    NAME_FOLDER = '.needle'
    NAME_CLI = '%s[needle]%s > ' % (Colors.C, Colors.N)

    # PATHS
    FOLDER_HOME = os.path.join(os.path.expanduser('~'), NAME_FOLDER)
    FOLDER_TEMP = os.path.join(FOLDER_HOME, 'tmp')
    FOLDER_BACKUP = os.path.join(FOLDER_HOME, 'backup')
    FILE_HISTORY = os.path.join(FOLDER_HOME, 'needle_history')
    FILE_DB = 'issues.db'

    # ==================================================================================================================
    # GLOBALS & AGENT
    # ==================================================================================================================
    # GLOBAL OPTIONS
    GLOBAL_IP = '127.0.0.1'
    GLOBAL_PORT = '2222'
    GLOBAL_AGENT_PORT = '4444'
    GLOBAL_USERNAME = 'root'
    GLOBAL_PASSWORD = 'alpine'
    GLOBAL_DEBUG = False
    GLOBAL_VERBOSE = True
    GLOBAL_OUTPUT_FOLDER = os.path.join(FOLDER_HOME, 'output')
    GLOBAL_PUB_KEY_AUTH = True
    GLOBAL_SAVE_HISTORY = True
    GLOBAL_SKIP_OUTPUT_FOLDER_CHECK = False
    GLOBAL_HIDE_SYSTEM_APPS = False
    PASSWORD_CLEAR = 'password_clear'
    PASSWORD_MASK = '********'

    # AGENT CONSTANTS
    AGENT_TAG = "[AGENT]"
    AGENT_WELCOME = "Welcome to Needle Agent"
    AGENT_VERSION_MARK = "VERSION: "
    AGENT_OUTPUT_END = " :OUTPUT_END:"
    AGENT_TIMEOUT_READ = 5
    AGENT_CMD_STOP = "stop"
    AGENT_CMD_OS_VERSION = "os_version"
    AGENT_CMD_LIST_APPS = "list_apps"

    # MODULE COMPATIBILITY
    MODULES_DISABLED = {
        '10': [
            'binary/installation/install',
            'binary/installation/pull_ipa',
        ]
    }

    # ==================================================================================================================
    # LOCAL
    # ==================================================================================================================
    # LOCAL TOOLS
    PATH_LIBS = os.path.join(sys.path[0], 'libs')
    PATH_DEVICETOOLS = os.path.join(PATH_LIBS, 'devicetools')
    PATH_TOOLS_LOCAL = {
        'ADVTRUSTSTORE': os.path.join(PATH_LIBS, 'ADVTrustStore/TrustManager.py'),
        'BINARYCOOKIEREADER': os.path.join(PATH_LIBS, 'binarycookiereader/binarycookiereader.py'),
        'CAT': 'cat',
        'CURL': 'curl',
        'DIFF': 'diff',
        'EOG': 'eog',
        'FRIDA': 'frida',
        'FRIDA-TRACE': 'frida-trace',
        'GREP': 'grep',
        'IDEVICESYSLOG': 'idevicesyslog',
        'MITMDUMP': 'mitmdump',
        'NANO': 'nano',
        'OPEN': 'open',
        'OPENSSL': 'openssl',
        'SECURITY': 'security',
        'SQLITE3': 'sqlite3',
        'TCPRELAY': os.path.join(PATH_LIBS, 'usbmuxd/tcprelay.py'),
        'VIM': 'vim',
    }
    DISABLE_HOST_VERIFICATION = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'

    # ==================================================================================================================
    # DEVICE
    # ==================================================================================================================
    # DEVICE PATHS
    DEVICE_PATH_TEMP_FOLDER  = '/var/root/needle/'
    DEVICE_PATH_TRUST_STORE  = '/private/var/Keychains/TrustStore.sqlite3'
    DEVICE_PATH_FRIDA_CACHE  = '/Library/Caches/frida-*'
    DEVICE_PATH_HOSTS        = '/etc/hosts'
    DEVICE_PATH_EFFECTIVE_USER_SETTINGS_IOS9_AND_BELOW = '/var/mobile/Library/ConfigurationProfiles/EffectiveUserSettings.plist'
    DEVICE_PATH_EFFECTIVE_USER_SETTINGS_IOS10 = '/var/mobile/Library/UserConfigurationProfiles/EffectiveUserSettings.plist'

    # DEVICE TOOLS
    FRIDA_PORT = 27042
    DEBUG_PORT = 12345
    PREFERRED_ARCH = 'armv7'
    CA_MITM_URL = 'http://mitm.it/cert/pem'
    CA_BURP_URL = 'http://burp/cert'
    CYDIA_LIST = '/etc/apt/sources.list.d/cydia.list'
    THEOS_FOLDER = '/private/var/theos/'
    DEVICE_SETUP = {
        'PREREQUISITES': ['apt-get', 'dpkg'],
        'TOOLS': {
            # Installation modes supported:
            #   - PACKAGES  = None && LOCAL  = None --> don't install the tools (prerequisite, etc.)
            #   - PACKAGES != None && LOCAL  = None --> add repo if not None, then use apt-get to install the tool
            #   - PACKAGES  = None && LOCAL != None --> use local installation

            # UNIX UTILITIES
            'APT-GET': {'COMMAND': 'apt-get', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'DPKG': {'COMMAND': 'dpkg', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'FIND': {'COMMAND': 'find', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'GAWK': {'COMMAND': 'awk', 'PACKAGES': ['gawk'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'WHICH': {'COMMAND': 'which', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'LIPO': {'COMMAND': 'lipo', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'PLUTIL': {'COMMAND': 'plutil', 'PACKAGES': ['com.ericasadun.utilities'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'UNZIP':  {'COMMAND': 'unzip', 'PACKAGES': ['unzip'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'STRINGS': {'COMMAND': 'strings', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},

            # TOOLKITS
            'COREUTILS': {'COMMAND': None, 'PACKAGES': ['coreutils', 'coreutils-bin'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'DARWINTOOLS': {'COMMAND': None, 'PACKAGES': ['org.coolstar.cctools'], 'REPO': None, 'LOCAL': None, 'SETUP': None},

            # TOOLS
            'CYCRIPT': {'COMMAND': 'cycript', 'PACKAGES': ['cycript'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'FRIDA': {'COMMAND': 'frida', 'PACKAGES': ['re.frida.server'], 'REPO': 'https://build.frida.re/', 'LOCAL': None, 'SETUP': None},
            'FRIDA32BIT': {'COMMAND': 'frida', 'PACKAGES': ['re.frida.server32'], 'REPO': 'https://build.frida.re/', 'LOCAL': None, 'SETUP': None},
            'GDB': {'COMMAND': 'gdb', 'PACKAGES': ['gdb'], 'REPO': 'http://cydia.radare.org/', 'LOCAL': None, 'SETUP': None},
            'THEOS': {'COMMAND': 'theos', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': [
                "ln -s /usr/local/bin/perl /usr/bin/perl",
                "GIT_SSL_NO_VERIFY=true git clone --recursive https://github.com/theos/theos.git %s" % THEOS_FOLDER,
                "mkdir -p %ssdks" % THEOS_FOLDER,
                "curl -ksL \"https://sdks.website/dl/iPhoneOS8.1.sdk.tbz2\" | tar -xj -C %ssdks" % THEOS_FOLDER,
                "curl -ksL \"https://sdks.website/dl/iPhoneOS9.3.sdk.tbz2\" | tar -xj -C %ssdks" % THEOS_FOLDER,
            ]},
            'THEOS_NIC': {'COMMAND': '%sbin/nic.pl' % THEOS_FOLDER, 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},

            # TO REPLACE
            'CLASS-DUMP': {'COMMAND': 'class-dump', 'PACKAGES': ['pcre', 'net.limneos.classdump-dyld', 'class-dump'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'CLUTCH': {'COMMAND': 'Clutch2', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': [
                "curl -ksL \"http://cydia.iphonecake.com/Clutch2.0.4.deb\" -o /var/root/clutch.deb",
                "dpkg -i /var/root/clutch.deb && rm -f /var/root/clutch.deb",
                "killall -HUP SpringBoard"
            ]},
            'CURL': {'COMMAND': 'curl', 'PACKAGES': ['curl'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'FILEDP': {'COMMAND': 'FileDP', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'FileDP'), 'SETUP': None},
            'FSMON': {'COMMAND': 'fsmon', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'fsmon'), 'SETUP': None},
            'IPAINSTALLER': {'COMMAND': 'ipainstaller', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'KEYCHAIN_DUMP': {'COMMAND': 'keychain_dump', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'keychain_dump'), 'SETUP': None},
            'ONDEVICECONSOLE': {'COMMAND': 'ondeviceconsole', 'PACKAGES': ['com.eswick.ondeviceconsole'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'OPEN': {'COMMAND': 'open', 'PACKAGES': ['com.conradkramer.open'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'OTOOL': {'COMMAND': 'otool', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'PBWATCHER': {'COMMAND': 'pbwatcher', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'pbwatcher'), 'SETUP': None},
            'PERL': {'COMMAND': 'perl', 'PACKAGES': ['org.coolstar.perl', 'org.coolstar.iostoolchain'], 'REPO': 'http://coolstar.org/publicrepo/', 'LOCAL': None, 'SETUP': None},
            'SCP': {'COMMAND': 'scp', 'PACKAGES': ['org.coolstar.scp-sftp-dropbear'], 'REPO': 'https://coolstar.org/publicrepo/', 'LOCAL': None, 'SETUP': None},
            'UIOPEN': {'COMMAND': 'uiopen', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
        }
    }
    DEVICE_TOOLS = dict([(k, v['COMMAND']) for k, v in DEVICE_SETUP['TOOLS'].iteritems() if v['COMMAND'] is not None])
