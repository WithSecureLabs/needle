from core.framework.module import BackgroundModule


class Module(BackgroundModule):
    meta = {
        'name': 'Title',
        'author': '@AUTHOR (@TWITTER)',
        'description': 'Description',
        'options': (
        ),
    }

    # ==================================================================================================================
    # UTILS
    # ==================================================================================================================

    # ==================================================================================================================
    # RUN
    # ==================================================================================================================
    def module_run(self):
        """Main Execution"""
        pass

    def module_kill(self):
        """Code to be run when the user choose to kill the job. Useful for closing running tasks and exporting results"""
        pass
