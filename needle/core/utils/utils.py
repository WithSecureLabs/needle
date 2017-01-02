import os
import re
import io
import json
import biplist
import plistlib
from pprint import pprint


# ======================================================================================================================
# GENERAL UTILS
# ======================================================================================================================
class Utils(object):
    # ==================================================================================================================
    # PATH UTILS
    # ==================================================================================================================
    @staticmethod
    def escape_path(path):
        """Escape the given path."""
        import pipes
        path = path.strip()          # strip
        path = path.strip(''''"''')  # strip occasional single/double quotes from both sides
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
        try:
            json.dump(text, fp, indent=4)
        except TypeError as e:
            raise Exception(e)

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
        """Read a plist from file."""
        try:
            plist = biplist.readPlist(path)
            return plist
        except (biplist.InvalidPlistException, biplist.NotBinaryPlistException), e:
            raise Exception("Failed to parse plist file: {}".format(e))

    @staticmethod
    def plist_read_from_string(text):
        """Read a plist from string."""
        Utils.plist_read_from_file(io.BytesIO(text))

    @staticmethod
    def plist_write_to_file(text, fp):
        """Write a plist to file."""
        Utils.dict_write_to_file(text, fp)
