"""Private worker errors carry fixed codes, never native diagnostics or source text."""
class Rejection(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def reject(code):
    raise Rejection(code)
