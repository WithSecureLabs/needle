from core.framework.module import BaseModule
from core.utils.utils import Utils

class Module(BaseModule):
    meta = {
        'name': 'Plist Files',
        'author': '@JoshCGrossman (@ComsecGlobal) heavily based on files_plist.py by @LanciniMarco (@MWRLabs)',
        'description': 'Dump all plist files contained in the app folders to the specified output directory.',
        'options': (
            ('output', True, False, 'Full path of the output directory (Note the trailing /)'),
            ('silent', True, False, 'Silent mode - Will not print file contents to screen'),			
        ),
        'comments': ['The module will build file names based on each file\'s path (changing the / symbol to the _ symbol)', 
        'It will overwrite any existing files in the output directory']
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        sub_directory = 'Plist/'
        self.options['output'] = self.local_op.build_temp_path_for_file(self, "") + sub_directory

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        
        self.printer.info("Looking for Plist files...")

        # Compose cmd string
        dirs = [self.APP_METADATA['bundle_directory'], self.APP_METADATA['data_directory']]
        dirs_str = ' '.join(dirs)
        cmd = '{bin} {dirs_str} -type f -name "*.plist"'.format(bin=self.device.DEVICE_TOOLS['FIND'], dirs_str=dirs_str)
        out = self.device.remote_op.command_blocking(cmd)

        # No files found
        if not out:
            self.printer.info("No Plist files found")
            return
   
        # Create the sub directory in the output directory to hold the file
        self.local_op.dir_create(self.options['output']) if self.options['output'] else None				
		
		
        for fname in out:
            
            
            fname = Utils.escape_path(fname.strip())
			
			# Remove folder path from the file name to be used when saving in the output directory.
            shortname = fname.replace(self.APP_METADATA['bundle_directory'],'')
            shortname = shortname.replace(self.APP_METADATA['data_directory'],'')
			
			# Remove extraneous ' symbol
            shortname = shortname.replace('\'','')
            
			# We want to convert the directory path to a simple filename so swap the / symbol for a _ symbol
            shortname = shortname.replace('/','_')
			
            # Run plutil
            self.printer.info("Dumping content of the file:" + fname)
            pl = self.device.remote_op.parse_plist(fname)
            
            # Print (if the silent option was set to False) & save to file
            outfile = self.options['output'] + str(shortname) if self.options['output'] else None
            self.printer.info(outfile)
            self.print_cmd_output(pl, outfile, self.options['silent'])