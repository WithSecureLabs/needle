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

    # GLOBAL OPTIONS
    GLOBAL_IP = '127.0.0.1'
    GLOBAL_PORT = '2222'
    GLOBAL_USERNAME = 'root'
    GLOBAL_PASSWORD = 'alpine'
    GLOBAL_DEBUG = False
    GLOBAL_VERBOSE = True
    GLOBAL_SETUP_DEVICE = True

    # LOCAL TOOLS
    PATH_LIBS = os.path.join(sys.path[0], 'libs')
    PATH_DEVICETOOLS = os.path.join(PATH_LIBS, 'devicetools')
    PATH_TOOLS_LOCAL = {
        'ADVTRUSTSTORE': os.path.join(PATH_LIBS, 'ADVTrustStore/TrustManager.py'),
        'BINARYCOOKIEREADER': os.path.join(PATH_LIBS, 'binarycookiereader/binarycookiereader.py'),
        'TCPRELAY': os.path.join(PATH_LIBS, 'usbmuxd/tcprelay.py'),
        'IDEVICESYSLOG': 'idevicesyslog',
        'SQLITE3': 'sqlite3',
        'DIFF': 'diff',
        'EOG': 'eog',
        'GREP': 'grep',
        'FRIDA': 'frida',
        'FRIDA-TRACE': 'frida-trace',
        'CAT': 'cat',
        'MITMDUMP': 'mitmdump',
    }
    DISABLE_HOST_VERIFICATION = '-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no'

    # DEVICE PATHS
    DEVICE_PATH_TEMP_FOLDER  = '/var/root/needle/'
    DEVICE_PATH_APPLIST_iOS7 = '/var/mobile/Library/Caches/com.apple.mobile.installation.plist'
    DEVICE_PATH_APPLIST_iOS8 = '/var/mobile/Library/MobileInstallation/LastLaunchServicesMap.plist'
    DEVICE_PATH_BUNDLE_iOS7  = '/private/var/mobile/Applications/'
    DEVICE_PATH_BUNDLE_iOS8  = '/private/var/mobile/Containers/Bundle/Application/'
    DEVICE_PATH_DATA_iOS8    = '/private/var/mobile/Containers/Data/Application/'
    DEVICE_PATH_TRUST_STORE  = '/private/var/Keychains/TrustStore.sqlite3'
    DEVICE_PATH_FRIDA_CACHE  = '/Library/Caches/frida-*'

    # DEVICE TOOLS
    FRIDA_PORT = 27042
    DEBUG_PORT = 12345
    CA_MITM_URL = 'http://mitm.it/cert/pem'
    CYDIA_LIST = '/etc/apt/sources.list.d/cydia.list'
    DEVICE_SETUP = {
        'PREREQUISITES': ['apt-get', 'dpkg'],
        'TOOLS': {
            # Installation modes supported:
            #   - PACKAGES  = None && LOCAL  = None --> don't install the tools (prerequisite, etc.)
            #   - PACKAGES != None && LOCAL  = None --> add repo if not None, then use apt-get to install the tool
            #   - PACKAGES  = None && LOCAL != None --> use local installation

            # BASIC COMMANDS
            'APT-GET': {'COMMAND': 'apt-get', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},
            'DPKG': {'COMMAND': 'dpkg', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},
            'WHICH': {'COMMAND': 'which', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},
            'UNZIP':  {'COMMAND': 'unzip', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},

            # TOOLKITS
            'BIGBOSS': {'COMMAND': None, 'PACKAGES': ['bigbosshackertools'], 'REPO': 'http://apt.thebigboss.org/repofiles/cydia/', 'LOCAL': None},
            'DARWINTOOLS': {'COMMAND': None, 'PACKAGES': ['org.coolstar.cctools'], 'REPO': None, 'LOCAL': None},
            'COREUTILS': {'COMMAND': None, 'PACKAGES': ['coreutils-bin'], 'REPO': None, 'LOCAL': None},

            # PROGRAMS
            'CLASS-DUMP': {'COMMAND': '/usr/bin/class-dump', 'PACKAGES': ['pcre', 'net.limneos.classdump-dyld', 'class-dump'], 'REPO': '', 'LOCAL': None},
            'CLUTCH': {'COMMAND': '/usr/bin/Clutch2', 'PACKAGES': ['com.iphonecake.clutch2'], 'REPO': 'http://cydia.iphonecake.com/', 'LOCAL': None},
            'CYCRIPT': {'COMMAND': '/usr/bin/cycript', 'PACKAGES': ['cycript'], 'REPO': None, 'LOCAL': None},
            #'DEBUGSERVER': {'COMMAND': '/usr/bin/debugserver', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'debugserver_81')},
            'FILEDP': {'COMMAND': '/usr/bin/FileDP', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'FileDP')},
            'FIND': {'COMMAND': '/usr/bin/find', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},
            'FRIDA': {'COMMAND': '/usr/bin/frida', 'PACKAGES': ['re.frida.server'], 'REPO': 'https://build.frida.re/', 'LOCAL': None},
            'FSMON': {'COMMAND': '/usr/bin/fsmon', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'fsmon')},
            'GDB': {'COMMAND': '/usr/bin/gdb', 'PACKAGES': ['gdb'], 'REPO': 'http://cydia.radare.org/', 'LOCAL': None},
            'IPAINSTALLER': {'COMMAND': '/usr/bin/ipainstaller', 'PACKAGES': ['com.autopear.installipa'], 'REPO': None, 'LOCAL': None},
            'KEYCHAINEDITOR': {'COMMAND': '/usr/bin/keychaineditor', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'keychaineditor')},
            'LDID': {'COMMAND': '/usr/bin/ldid', 'PACKAGES': ['ldid'], 'REPO': None, 'LOCAL': None},
            'LIPO': {'COMMAND': '/usr/bin/lipo', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},
            'OPEN': {'COMMAND': '/usr/bin/open', 'PACKAGES': ['com.conradkramer.open'], 'REPO': None, 'LOCAL': None},
            'OTOOL': {'COMMAND': '/usr/bin/otool', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},
            'PBWATCHER': {'COMMAND': '/usr/bin/pbwatcher', 'PACKAGES': None, 'REPO': None, 'LOCAL': os.path.join(PATH_DEVICETOOLS, 'pbwatcher')},
            'PLUTIL': {'COMMAND': '/usr/bin/plutil', 'PACKAGES': ['com.ericasadun.utilities'], 'REPO': None, 'LOCAL': None},
            'SOCAT': {'COMMAND': '/usr/bin/socat', 'PACKAGES': ['socat'], 'REPO': None, 'LOCAL': None},
            'STRINGS': {'COMMAND': '/usr/bin/strings', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},
            'UIOPEN': {'COMMAND': '/usr/bin/uiopen', 'PACKAGES': None, 'REPO': None, 'LOCAL': None},
        }
    }
    DEVICE_TOOLS = dict([(k, v['COMMAND']) for k, v in DEVICE_SETUP['TOOLS'].iteritems() if v['COMMAND'] is not None])
