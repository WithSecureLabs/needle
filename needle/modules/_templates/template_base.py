from core.framework.module import BaseModule


class Module(BaseModule):
    meta = {
        'name': 'Test Module',
        'author': '@AUTHOR (@TWITTER)',
        'description': 'Description',
        'options': (
            ('name', False, True, 'description'),
            ('output', True, False, 'Full path of the output file')
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================
    def __init__(self, params):
        BaseModule.__init__(self, params)
        # Any other customization goes here

        # Setting default output file
        # self.options['output'] = self.local_op.build_output_path_for_file("template.txt", self)

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        self.printer.info("This is a template")
