"""Re-export of anti_cheat module for alternative import naming."""

from anti_cheat import *
from anti_cheat import main

if __name__ == "__main__":
    import sys
    sys.exit(main())
