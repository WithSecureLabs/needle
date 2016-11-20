import os
import re


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
