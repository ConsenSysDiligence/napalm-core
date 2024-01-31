import napalm.package
import napalm_core


def entry_point():
    """This is the entry point for the napalm package.

    It provisions your detection modules and provides them to napalm.

    It returns a dictionary of Collections, keyed by the name of the collection.
    """
    return napalm.package.entry_point(napalm_core)
