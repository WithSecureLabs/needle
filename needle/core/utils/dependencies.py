from printer import Printer


# ======================================================================================================================
# DEPENDENCIES CHECK
# ======================================================================================================================
def check_dependencies():
    """Check if the dependencies listed in requirements.txt and requirements-debian.txt has been satisfied.
    Exit otherwise."""
    import os, sys, platform
    printer = Printer()

    def python(fname):
        """Python dependencies."""
        import pkg_resources
        # Load from requirements.txt
        with open(fname, 'rb') as fp:
            dependencies = [x.strip() for x in fp.readlines()]
        # Check dependencies
        try:
            pkg_resources.require(dependencies)
        except pkg_resources.DistributionNotFound as e:
            printer.error('Distribution Not Found: %s' % e)
            printer.error('Please install the requirements listed in requirements.txt')
            sys.exit()
        except pkg_resources.VersionConflict as e:
            printer.debug('Version Conflict: %s' % e)
            printer.debug('Some features might not work as expected')

    def debian(fname):
        """Debian dependencies."""
        import apt
        # Load from requirements-debian.txt
        with open(fname, 'rb') as fp:
            dependencies = [x.strip() for x in fp.readlines()]
        # Check dependencies
        cache = apt.Cache()
        try:
            for pk in dependencies:
                pkg = cache[pk]
                if not pkg.is_installed:
                    printer.error('Package Not Found: %s' % pk)
                    printer.error('Please install the requirements listed in requirements-debian.txt')
                    sys.exit()
        except Exception as e:
            printer.error('Package Not Found: %s' % e)
            printer.error('Please install the requirements listed in requirements-debian.txt')
            sys.exit()

    # Check requirements
    if platform.system() == 'Linux':

    python(os.path.join(os.path.abspath(sys.path[0]), 'requirements.txt'))
    debian(os.path.join(os.path.abspath(sys.path[0]), 'requirements-debian.txt'))
