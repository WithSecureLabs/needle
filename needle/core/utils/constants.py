import os
import sys

from ..utils.printer import Colors


class Constants(object):
    # AUTHOR
    AUTHOR = 'MWR InfoSecurity (@MWRLabs) - Marco Lancini (@LanciniMarco)'
    EMAIL = 'marco.lancini[at]mwrinfosecurity.com'
    WEBSITE = 'mwr.to/needle'

    # Name variables
    NAME = 'Needle'
    NAME_FOLDER = '.needle'
    NAME_CLI = '%s[needle]%s > ' % (Colors.C, Colors.N)

    # PATHS
    FOLDER_HOME = os.path.join(os.path.expanduser('~'), NAME_FOLDER)
    FOLDER_TEMP = os.path.join(FOLDER_HOME, 'tmp')
    FOLDER_BACKUP = os.path.join(FOLDER_HOME, 'backup')
    FILE_HISTORY = os.path.join(FOLDER_HOME, 'needle_history')

    # GLOBAL OPTIONS
    GLOBAL_IP = '127.0.0.1'
    GLOBAL_PORT = '2222'
    GLOBAL_USERNAME = 'root'
    GLOBAL_PASSWORD = 'alpine'
    GLOBAL_DEBUG = False
    GLOBAL_VERBOSE = True
    GLOBAL_SETUP_DEVICE = False
    GLOBAL_OUTPUT_FOLDER = os.path.join(FOLDER_HOME, 'output')
    GLOBAL_PUB_KEY_AUTH = True
    GLOBAL_SAVE_HISTORY = True
    PASSWORD_CLEAR = 'password_clear'
    PASSWORD_MASK = '********'

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

    # DEVICE PATHS
    DEVICE_PATH_TEMP_FOLDER  = '/var/root/needle/'
    DEVICE_PATH_APPLIST_iOS7 = '/var/mobile/Library/Caches/com.apple.mobile.installation.plist'
    DEVICE_PATH_APPLIST_iOS8 = '/var/mobile/Library/MobileInstallation/LastLaunchServicesMap.plist'
    DEVICE_PATH_APPLIST_iOS9 = '/private/var/installd/Library/MobileInstallation/LastLaunchServicesMap.plist'
    DEVICE_PATH_APPLIST_iOS10 = '/private/var/installd/Library/MobileInstallation/LastLaunchServicesMap.plist'
    DEVICE_PATH_BUNDLE_iOS7  = '/private/var/mobile/Applications/'
    DEVICE_PATH_BUNDLE_iOS8  = '/private/var/mobile/Containers/Bundle/Application/'
    DEVICE_PATH_BUNDLE_iOS9  = '/private/var/containers/Bundle/Application/'
    DEVICE_PATH_DATA_iOS8    = '/private/var/mobile/Containers/Data/Application/'
    DEVICE_PATH_DATA_iOS9    = '/private/var/mobile/Containers/Data/Application/'
    DEVICE_PATH_TRUST_STORE  = '/private/var/Keychains/TrustStore.sqlite3'
    DEVICE_PATH_FRIDA_CACHE  = '/Library/Caches/frida-*'
    DEVICE_PATH_HOSTS        = '/etc/hosts'

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

            # BASIC COMMANDS
            'APT-GET': {'COMMAND': 'apt-get', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'DPKG': {'COMMAND': 'dpkg', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'WHICH': {'COMMAND': 'which', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'UNZIP':  {'COMMAND': 'unzip', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},

            # TOOLKITS
            'BIGBOSS': {'COMMAND': None, 'PACKAGES': ['bigbosshackertools'], 'REPO': 'http://apt.thebigboss.org/repofiles/cydia/', 'LOCAL': None, 'SETUP': None},
            'DARWINTOOLS': {'COMMAND': None, 'PACKAGES': ['org.coolstar.cctools'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'COREUTILS': {'COMMAND': None, 'PACKAGES': ['coreutils', 'coreutils-bin'], 'REPO': None, 'LOCAL': None, 'SETUP': None},

            # PROGRAMS
            'CLASS-DUMP': {'COMMAND': 'class-dump', 'PACKAGES': ['pcre', 'net.limneos.classdump-dyld', 'class-dump'], 'REPO': '', 'LOCAL': None, 'SETUP': None},
            'CLUTCH': {'COMMAND': 'Clutch2', 'PACKAGES': ['com.iphonecake.clutch2'], 'REPO': 'http://cydia.iphonecake.com/', 'LOCAL': None, 'SETUP': None},
            'CYCRIPT': {'COMMAND': 'cycript', 'PACKAGES': ['cycript'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'FILEDP': {'COMMAND': 'FileDP', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'FileDP'), 'SETUP': None},
            'FIND': {'COMMAND': 'find', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'FRIDA': {'COMMAND': 'frida', 'PACKAGES': ['re.frida.server'], 'REPO': 'https://build.frida.re/', 'LOCAL': None, 'SETUP': None},
            'FSMON': {'COMMAND': 'fsmon', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'fsmon'), 'SETUP': None},
            'GDB': {'COMMAND': 'gdb', 'PACKAGES': ['gdb'], 'REPO': 'http://cydia.radare.org/', 'LOCAL': None, 'SETUP': None},
            'IPAINSTALLER': {'COMMAND': 'ipainstaller', 'PACKAGES': ['com.autopear.installipa'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'KEYCHAIN_DUMP': {'COMMAND': 'keychain_dump', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'keychain_dump'), 'SETUP': None},
            'LDID': {'COMMAND': 'ldid', 'PACKAGES': ['ldid'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'LIPO': {'COMMAND': 'lipo', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'ONDEVICECONSOLE': {'COMMAND': 'ondeviceconsole', 'PACKAGES': ['com.eswick.ondeviceconsole'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'OPEN': {'COMMAND': 'open', 'PACKAGES': ['com.conradkramer.open'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'OTOOL': {'COMMAND': 'otool', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'PBWATCHER': {'COMMAND': 'pbwatcher', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'pbwatcher'), 'SETUP': None},
            'PERL': {'COMMAND': 'perl', 'PACKAGES': ['org.coolstar.perl', 'org.coolstar.iostoolchain'], 'REPO': 'http://coolstar.org/publicrepo/', 'LOCAL': None, 'SETUP': None},
            'PLUTIL': {'COMMAND': 'plutil', 'PACKAGES': ['com.ericasadun.utilities'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'PREFERENCELOADER': {'COMMAND': None, 'PACKAGES': ['preferenceloader'], 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'STRINGS': {'COMMAND': 'strings', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'SSLKILLSWITCH': {'COMMAND': None, 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': [
                "curl -ksL \"https://github.com/iSECPartners/ios-ssl-kill-switch/releases/download/release-0.6/com.isecpartners.nabla.sslkillswitch_v0.6-iOS_7.0.deb\" -o /var/root/kill.deb",
                "dpkg -i /var/root/kill.deb && rm -f /var/root/kill.deb",
                "killall -HUP SpringBoard"
            ]},
            'THEOS': {'COMMAND': 'theos', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': [
                "ln -s /usr/local/bin/perl /usr/bin/perl",
                "GIT_SSL_NO_VERIFY=true git clone --recursive https://github.com/theos/theos.git %s" % THEOS_FOLDER,
                "mkdir -p %ssdks" % THEOS_FOLDER,
                "curl -ksL \"https://sdks.website/dl/iPhoneOS8.1.sdk.tbz2\" | tar -xj -C %ssdks" % THEOS_FOLDER,
                "curl -ksL \"https://sdks.website/dl/iPhoneOS9.3.sdk.tbz2\" | tar -xj -C %ssdks" % THEOS_FOLDER,
            ]},
            'THEOS_NIC': {'COMMAND': '%sbin/nic.pl' % THEOS_FOLDER, 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
            'UIOPEN': {'COMMAND': 'uiopen', 'PACKAGES': None, 'REPO': None, 'LOCAL': None, 'SETUP': None},
        }
    }
    DEVICE_TOOLS = dict([(k, v['COMMAND']) for k, v in DEVICE_SETUP['TOOLS'].iteritems() if v['COMMAND'] is not None])
