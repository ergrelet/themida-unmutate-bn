# Note(ergrelet): this file is meant to be used by Binary Ninja when loading our plugin.
try:
    import importlib

    importlib.import_module("binaryninja")
    from .binja_plugin import plugin_init

    plugin_init()
except ImportError:
    pass