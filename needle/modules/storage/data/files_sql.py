from core.framework.module import BaseModule
from core.utils.menu import choose_from_list_data_protection
from core.utils.utils import Utils


class Module(BaseModule):
    meta = {
        'name': 'SQL Files',
        'author': '@LanciniMarco (@MWRLabs)',
        'description': 'List SQL files contained in the app folders, alongside with their Data Protection Class. '
                       'Plus, offers the chance to pull and inspect them with SQLite3 or to dump them all for local analysis.',
        'options': (
            ('analyze', True, True, 'Prompt to pick one file to analyze'),
            ('dump_all', False, True, 'Retrieve all SQL files'),
            ('row_counts', True, False, 'Prints the number of rows in all database tables if '
                                         'ANALYZE is also True'),
            ('output', True, False, 'Full path of the output folder'),
            ('headers', True, True, 'Enable SQLite3 table headers'),
            ('column_mode', True, True, 'Enable SQLite3 column mode'),
            ('csv_mode', False, True, 'Enable SQLite3 CSV mode'),
        ),
        'comments': [
            '"DUMP_ALL" will build file names based on each file\'s path (changing the / symbol to the _ symbol)',
            'It will overwrite any existing files in the output directory']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self._global_options['output_folder']

    def _print_rows(self, fname):
        self.printer.notify("Getting table row counts...")
        # Get all tables
        sql = '.tables'
        cmd = '{bin} {db} "{sql}"'.format(bin=self.TOOLS_LOCAL['SQLITE3'],
                                          db=fname, sql=sql)
        out = self.local_op.command_blocking(cmd)
        # Get row counts for all the tables
        sql = ''
        for line in out:
            for item in line.split():
                sql += "SELECT '{item}' as 'Table', count (*) as 'Rows' from {item} UNION ".format(item=item)
        if sql:
            # Trim off the final 'UNION' from the query
            sql = sql[:len(sql)-6]
            cmd = '{bin} {db} "{sql}"'.format(bin=self.TOOLS_LOCAL['SQLITE3'],
                                          db=fname, sql=sql)
            out = self.local_op.command_blocking(cmd)
            out_parsed = filter(None, out[0].split('\n'))
            # Print the result to screen
            rows = []
            for elem in out_parsed:
                tmp = elem.split('|')
                rows.append([tmp[0], tmp[1]])

            self.print_table(rows, header=['Table','Rows'])

    def analyze_file(self, fname):
        cmd_headers = ' -header' if self.options['headers'] else ''
        cmd_column = ' -column' if self.options['column_mode'] else ''
        cmd_csv = ' -csv' if self.options['csv_mode'] else ''
        # Print row count
        if self.options['row_counts']:
            self._print_rows(fname)
        # Spawn SQLite3 console
        self.printer.info("Spawning SQLite3 console...")
        cmd = '{bin} {header} {column} {csv} {db}'.format(bin=self.TOOLS_LOCAL['SQLITE3'],
                                                          header=cmd_headers, column=cmd_column, csv=cmd_csv,
                                                          db=fname)
        self.local_op.command_interactive(cmd)

    def save_file(self, remote_name, local_name, analyze=False):
        if not self.options['output']:
            return
        # Prepare path
        temp_name = 'sql_{}'.format(local_name)
        local_name = self.local_op.build_output_path_for_file(temp_name, self)
        # Save to file
        self.device.pull(remote_name, local_name)
        # Analyze
        if analyze: self.analyze_file(local_name)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("Looking for SQL files...")

        # Compose cmd string
        dirs = [self.APP_METADATA['bundle_directory'], self.APP_METADATA['data_directory']]
        dirs_str = ' '.join(dirs)
        cmd = '{bin} {dirs_str} -type f -name "*.sql" -o -name "*.sqlite" -o -name "*.db" -o -name "*.db3"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dirs_str)
        out = self.device.remote_op.command_blocking(cmd)

        # No files found
        if not out:
            self.printer.error("No SQL files found")
            return

        # Save list
        self.add_issue('SQL files detected', out, 'INVESTIGATE', None)

        # Add data protection class
        self.printer.info("Retrieving data protection classes...")
        retrieved_files = self.device.app.get_dataprotection(out)

        # Analysis
        self.printer.info("The following SQL files have been found:")
        if self.options['analyze']:
            # Show Menu
            remote_name = choose_from_list_data_protection(retrieved_files)
            local_name = self.device.app.convert_path_to_filename(remote_name, self.APP_METADATA)
            # Save it locally and analyze it
            self.save_file(remote_name, local_name, analyze=True)
        else:
            # Only list files, do not prompt the user
            choose_from_list_data_protection(retrieved_files, choose=False)

        # Dump all
        if self.options['dump_all']:
            self.printer.notify('Dumping all SQL files...')
            for fname in out:
                remote_name = Utils.escape_path(fname)
                # Convert the path to a valid filename
                local_name = self.device.app.convert_path_to_filename(fname, self.APP_METADATA)
                # Save it locally
                self.save_file(remote_name, local_name)
