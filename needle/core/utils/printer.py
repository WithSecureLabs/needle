from __future__ import print_function
import re

from utils import Utils


# ======================================================================================================================
# CUSTOM COLORS
# ======================================================================================================================
class Colors(object):
    N = '\033[m'    # native
    R = '\033[31m'  # red
    G = '\033[32m'  # green
    O = '\033[33m'  # orange
    B = '\033[34m'  # blue
    C = '\033[36m'  # cyan


# ======================================================================================================================
# CUSTOM LOGGING FUNCTION
# ======================================================================================================================
class Printer(object):
    """Centralized, custom logging object."""
    # ==================================================================================================================
    # INIT
    # ==================================================================================================================
    __instance = None
    is_debug = None
    is_verbose = None

    def __new__(cls, *args, **kwargs):
        """Printer needs to be a Singleton."""
        if not cls.__instance:
            cls.__instance = super(Printer, cls).__new__(cls, *args, **kwargs)
        return cls.__instance

    # ==================================================================================================================
    # MANIPULATE STATE
    # ==================================================================================================================
    def set_debug(self, val):
        self.is_debug = bool(val)

    def set_verbose(self, val):
        self.is_verbose = bool(val)

    # ==================================================================================================================
    # CUSTOMIZED LOGGING
    # ==================================================================================================================
    def debug(self, msg):
        """Formats and presents output if in debug mode (very verbose)."""
        if self.is_debug:
            msg = '%s[D]%s %s' % (Colors.O, Colors.N, Utils.to_unicode(msg))
            print(msg)

    def verbose(self, msg):
        """Formats and presents output if in verbose mode."""
        if self.is_verbose:
            msg = '%s[V]%s %s' % (Colors.C, Colors.N, Utils.to_unicode(msg))
            print(msg)

    def info(self, msg):
        """Formats and presents normal output."""
        msg = '%s[*]%s %s' % (Colors.B, Colors.N, Utils.to_unicode(msg))
        print(msg)

    def notify(self, msg):
        """Formats and presents important output."""
        msg = '%s[+]%s %s' % (Colors.G, Colors.N, Utils.to_unicode(msg))
        print(msg)

    def warning(self, msg):
        """Formats and presents warnings."""
        msg = '%s[?] %s%s' % (Colors.O, Utils.to_unicode(msg), Colors.N,)
        print(msg)

    def error(self, msg):
        """Formats and presents errors."""
        msg = '%s[!] %s%s' % (Colors.R, Utils.to_unicode(msg), Colors.N)
        print(msg)
