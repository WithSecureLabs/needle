from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Keyboard Autocomplete Caching',
        'author': '@zakmaples (@MWRLabs)',
        'description': "Dump the content of the keyboard's autocomplete databases in order to help "
                       "identify if sensitive information input into the application could be cached.",
        'options': (
            ('output', True, False, 'Full path of the output file'),
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Setting default output file
        self.options['output'] = self.local_op.build_output_path_for_file("keyboard_autocomplete.txt", self)

    def module_pre(self):
        return BaseModule.module_pre(self, bypass_app=True)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        # Run strings over files
        self.printer.info("Running strings over keyboard autocomplete databases...")

        # Run Strings
        cmd = '{bin} {dirs_str} -type f \( -iname "*dynamic-text.dat" -o' \
              ' -iname "dynamic.dat" -o -iname "lexicon.dat" \) ' \
              '-exec {strings} {{}} \;'.format(bin=self.device.DEVICE_TOOLS['FIND'],
                                               dirs_str="/var/mobile/Library/Keyboard/",
                                               strings=self.device.DEVICE_TOOLS['STRINGS'])
        out = self.device.remote_op.command_blocking(cmd)

        # Print output
        if out:
            self.printer.notify("The following content has been found:")
            self.print_cmd_output(out, self.options['output'])
            self.add_issue('Content of Keyboard Autocomplete', None, 'INVESTIGATE', self.options['output'])
