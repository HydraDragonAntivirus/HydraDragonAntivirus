import inspect


class lazy_import:
    """
    Delay importing a module until it is used
    """

    def __init__(self, name: str, as_name: str | None = None):
        self.globals = inspect.currentframe().f_back.f_globals
        self.as_name = as_name or name
        self.globals[self.as_name] = self
        self.name = name

    def __getattr__(self, attr):
        self.globals[self.as_name] = module = __import__(self.name)
        return getattr(module, attr)
