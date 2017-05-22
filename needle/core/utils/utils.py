import os
import re
import io
import time
import json
import biplist
import plistlib
from pprint import pprint
from datetime import datetime


# ======================================================================================================================
# GENERAL UTILS
# ======================================================================================================================
class Utils(object):
    # ==================================================================================================================
    # PATH UTILS
    # ==================================================================================================================
    @staticmethod
    def escape_path(path, escape_accent=False):
        """Escape the given path."""
        import pipes
        path = path.strip()          # strip
        path = path.strip(''''"''')  # strip occasional single/double quotes from both sides
        if escape_accent:
            # Find the accents/backquotes that do not have a backslash
            # in front of them and escape them.
            path = re.sub('(?<!\\\\)`', '\`', path)
        print "Returning path: {}".format(pipes.quote(path))
        return pipes.quote(path)

    @staticmethod
    def escape_path_scp(path):
        """To be correctly handled by scp, paths must be quoted 2 times."""
        temp = Utils.escape_path(path)
        return '''"%s"''' % temp

    @staticmethod
    def extract_filename_from_path(path):
        return os.path.basename(path)

    @staticmethod
    def extract_paths_from_string(str):
        # Check we have a correct number of quotes
        if str.count('"') == 4 or str.count("'") == 4:
            # Try to get from double quotes
            paths = re.findall(r'\"(.+?)\"', str)
            if len(paths) == 2: return paths[0], paths[1]
            # Try to get from single quotes
            paths = re.findall(r"\'(.+?)\'", str)
            if len(paths) == 2: return paths[0], paths[1]
        # Error
        return None, None

    @staticmethod
    def path_join(folder, file):
        return os.path.join(folder, file)

    # ==================================================================================================================
    # UNICODE STRINGS UTILS
    # ==================================================================================================================
    @staticmethod
    def to_unicode_str(obj, encoding='utf-8'):
        """Checks if obj is a string and converts if not."""
        if not isinstance(obj, basestring):
            obj = str(obj)
        obj = Utils.to_unicode(obj, encoding)
        return obj

    @staticmethod
    def to_unicode(obj, encoding='utf-8'):
        """Checks if obj is a unicode string and converts if not."""
        if isinstance(obj, basestring):
            if not isinstance(obj, unicode):
                obj = unicode(obj, encoding)
        return obj

    @staticmethod
    def regex_escape_str(text):
        """Make the string regex-ready by escaping it."""
        return re.escape(text)

    @staticmethod
    def regex_remove_control_chars(text):
        """Remove non-printable characters from string."""
        control_chars = ''.join(map(unichr, range(0, 32) + range(127, 160)))
        control_char_re = re.compile('[%s]' % re.escape(control_chars))
        return control_char_re.sub('', text)

    # ==================================================================================================================
    # DATA STRUCTURE UTILS
    # ==================================================================================================================
    @staticmethod
    def merge_dicts(*dict_args):
        """Given any number of dicts, shallow copy and merge into a new dict."""
        result = {}
        for dictionary in dict_args:
            result.update(dictionary)
        return result

    @staticmethod
    def dict_print(text):
        """Print a dictionary to screen."""
        pprint(text, indent=4)

    @staticmethod
    def dict_write_to_file(text, fp):
        """Print a dictionary to file."""

        def json_serial(obj):
            """
            JSON serializer for objects not serializable by default
            Currently handles:
            - datetime objects (based on: http://stackoverflow.com/a/22238613/7011779)
            - biplist.Uid based on just getting the representation of the object
            """
            # datetime
            if isinstance(obj, datetime):
                return obj.isoformat()
            # biplist.Uid
            if isinstance(obj, biplist.Uid):
                return repr(obj)
            raise TypeError("Type not serializable")

        try:
            json.dump(text, fp, indent=4, default=json_serial)
        except TypeError as e:
            raise Exception(e)

    @staticmethod
    def string_to_json(text):
        """Convert a string to a JSON."""
        return json.loads(text)

    # ==================================================================================================================
    # PLIST UTILS
    # ==================================================================================================================
    @staticmethod
    def is_plist(text):
        """Checks if text is a plist."""
        content_type = type(text)
        return content_type is plistlib._InternalDict

    @staticmethod
    def plist_print(text):
        """Print a plist to screen."""
        Utils.dict_print(text)

    @staticmethod
    def plist_read_from_file(path):
        """Recursively read a plist from a file."""
        def decode_nested_plist(inner_plist):
            """This method is designed to allow recursively decoding a plist file."""
            if hasattr(inner_plist,'iteritems'):
                for k, v in inner_plist.iteritems():
                    if isinstance(v, biplist.Data):
                        inner_plist[k] = Utils.plist_read_from_string(v)
            return inner_plist
        try:
            plist = biplist.readPlist(path)
            return decode_nested_plist(plist)
        except (biplist.InvalidPlistException, biplist.NotBinaryPlistException), e:
            raise Exception("Failed to parse plist file: {}".format(e))

    @staticmethod
    def plist_read_from_string(text):
        """Recursively read a plist from a file."""
        return Utils.plist_read_from_file(io.BytesIO(text))

    @staticmethod
    def plist_write_to_file(text, fp):
        """Write a plist to file."""
        Utils.dict_write_to_file(text, fp)


# ======================================================================================================================
# RETRY DECORATOR
# ======================================================================================================================
class Retry(object):
    default_exceptions = (Exception)

    def __init__(self, tries=3, exceptions=None, delay=0):
        """Decorator for retrying function if exception occurs."""
        self.tries = tries
        if exceptions is None:
            exceptions = Retry.default_exceptions
        self.exceptions = exceptions
        self.delay = delay
        self.actual_tries = 0

    def __call__(self, func):
        def wrapper(obj, *args, **kwargs):
            # Check who is calling: Device or NeedleAgent
            device = obj._device if 'NeedleAgent' in type(obj).__name__ else obj
            exception = None
            while self.actual_tries < self.tries:
                try:
                    return func(obj, *args, **kwargs)
                except self.exceptions, e:
                    self.actual_tries += 1
                    exception = e
                    device.printer.error(exception)
                    if str(e).find('`') > -1:
                        # Attempt to escape the command args[0] in order to escape the accent.
                        device.printer.debug("Attempting retry with the accents/backquotes escaped.")
                        if len(args) > 0:
                            print "Args: {}".format(args)
                            args = [Utils.escape_path(i) if idx == 0 else i
                                    for idx, i in enumerate(args)]
                    device.disconnect()
                    device.printer.warning("Resetting connection to device...")
                    device.connect()
                    device.printer.warning("Rerunning last command...")
                    time.sleep(self.delay)
            self.actual_tries = 0
            raise Exception("An error occurred and it was not possible to restore it ({} attempts failed)".format(self.tries))
        return wrapper
