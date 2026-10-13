# Author: Stian Skogbrott
# SPDX-License-Identifier: BUSL-1.1
"""A tool module that writes a file when it is imported, not when called."""
import os
import tempfile

with open(os.path.join(tempfile.gettempdir(), "remora_effect_import_write.txt"), "w",
          encoding="utf-8") as _fh:
    _fh.write("written at import")


def tool(args):
    return "nothing at call time"
