from __future__ import print_function
from contextlib import closing
import collections
import sqlite3

from ..utils.constants import Constants
from ..utils.menu import print_question
from ..utils.printer import Colors
from ..utils.utils import Utils


# ======================================================================================================================
# ISSUES
# ======================================================================================================================
class Issue(collections.OrderedDict):
    FIELD_LIST = ['app', 'module', 'name', 'content', 'confidence', 'outfile']

    def __init__(self, *args, **kwargs):
        fields = collections.OrderedDict(zip(self.FIELD_LIST, args))
        super(Issue, self).__init__(fields)

    def __setitem__(self, name, value):
        super(Issue, self).__setitem__(name, value)

    def __delitem__(self, name):
        super(Issue, self).__delitem__(name)

    def __repr__(self):
        return dict.__repr__(self)


# ======================================================================================================================
# ISSUE_MANAGER
# ======================================================================================================================
class IssueManager(object):

    CONFIDENCE_LEVELS = {
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'INVESTIGATE': 'INVESTIGATE',
        'INFORMATIONAL': 'INFORMATIONAL'
    }
    DB_TABLE_ISSUES = 'issues'

    def __init__(self, framework):
        self.framework = framework
        self.printer = self.framework.printer
        self._db = None
        self._issue_list = []

    # ==================================================================================================================
    # DB MANAGEMENT
    # ==================================================================================================================
    def db_setup(self, folder):
        """Calculate the DB full pathname and create all the tables needed."""
        self._db = Utils.path_join(folder, Constants.FILE_DB)
        self.printer.debug("Setting up issues database...")
        self._db_query('CREATE TABLE IF NOT EXISTS {} ({} TEXT)'.format(self.DB_TABLE_ISSUES, ' TEXT, '.join(Issue.FIELD_LIST)))

    def _db_get_tables(self):
        return [x[0] for x in self._db_query('SELECT name FROM sqlite_master WHERE type=\'table\'')]

    def _db_query(self, query, values=()):
        """Queries the database and returns the results as a list."""
        self.printer.debug('[DB] QUERY: {}'.format(query))
        if not self._db:
            self.db_setup(self.framework._global_options['output_folder'])

        with sqlite3.connect(self._db) as conn:
            with closing(conn.cursor()) as cur:
                if values:
                    self.printer.debug('[DB] VALUES: {}'.format(values))
                    cur.execute(query, values)
                else:
                    cur.execute(query)
                # a rowcount of -1 typically refers to a select statement
                if cur.rowcount == -1:
                    rows = cur.fetchall()
                    results = rows
                # a rowcount of 1 == success and 0 == failure
                else:
                    conn.commit()
                    results = cur.rowcount
                return results

    def _db_insert(self, table, data, unique_columns=[]):
        """Inserts items into database and returns the affected row count.
        table - the table to insert the data into
        data - the information to insert into the database table in the form of a dictionary
               where the keys are the column names and the values are the column values
        unique_columns - a list of column names that should be used to determine if the
                         information being inserted is unique"""
        # set module to the calling module unless the do_add command was used
        #data['module'] = 'user_defined' if 'do_add' in [x[3] for x in inspect.stack()] else self._modulename.split('/')[-1]
        # Sanitize the inputs to remove NoneTypes, blank strings, and zeros
        columns = [x for x in data.keys() if data[x]]
        # Make sure that module is not seen as a unique column
        unique_columns = [x for x in unique_columns if x in columns and x != 'module']
        # Exit if there is nothing left to insert
        if not columns:
            return 0
        if not unique_columns:
            query = u'INSERT INTO "%s" ("%s") VALUES (%s)' % (
                table,
                '", "'.join(columns),
                ', '.join('?' * len(columns))
            )
        else:
            query = u'INSERT INTO "%s" ("%s") SELECT %s WHERE NOT EXISTS(SELECT * FROM "%s" WHERE %s)' % (
                table,
                '", "'.join(columns),
                ', '.join('?' * len(columns)),
                table,
                ' and '.join(['"%s"=?' % (column) for column in unique_columns])
            )
        values = tuple([data[column] for column in columns] + [data[column] for column in unique_columns])
        self._db_query(query, values)

    # ==================================================================================================================
    # ISSUE MANAGEMENT
    # ==================================================================================================================
    def issue_add(self, *args):
        """Given a list of elements (in the FIELD_LIST order), creates a new Issue both in-memory and in the database."""
        new_issue = Issue(*args)
        # Avoid duplicates
        if new_issue not in self._issue_list:
            # Add to in-memory list
            self._issue_list.append(new_issue)
            # Add to db
            self._db_insert(self.DB_TABLE_ISSUES, new_issue, new_issue.keys())
            self.printer.debug('New issue added: {}'.format(new_issue['name']))

    def issue_add_manual(self):
        """Prompt the user to insert all the info needed to add an issue."""
        args = [print_question('Please insert {}: '.format(el)) for el in Issue.FIELD_LIST]
        self.issue_add(*args)

    def issue_load(self):
        """Load issues from db."""
        pass


    def issue_print(self):
        """Print all the issues to screen."""
        def _issue_render(issue):
            for key in issue.keys():
                self.printer.error('\t{}{:>20}:{} {:<30}'.format(Colors.R, key.title(), Colors.N, issue[key]))
            print('\n')

        if self._issue_list:
            self.printer.notify('The following issues have been identified:')
            for idx, issue in enumerate(self._issue_list):
                self.printer.error("{}ISSUE #{}{}".format(Colors.R, idx, Colors.N))
                _issue_render(issue)
        else:
            self.printer.error('NO ISSUES FOUND')
