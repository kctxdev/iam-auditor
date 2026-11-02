import sys

from .cli import main

try:
    code = main()
except BrokenPipeError:  # ex.: | head
    code = 0
except KeyboardInterrupt:
    print("\ninterrompido.", file=sys.stderr)
    code = 130
raise SystemExit(code)
