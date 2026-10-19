#!/usr/bin/env python3
"""Create a source-only submission archive, excluding runtime and build artifacts."""
import gzip
from fnmatch import fnmatch
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / 'submission.tar.gz'
EXCLUDED = {'node_modules', 'target', 'build', '__pycache__', '.pytest_cache', 'results',
            '.DS_Store', 'keys', 'testbed', 'venv'}
EXCLUDED_FILES = ('*.pdf', '*.log', '*.stderr', '*.stdout', '*.sqlite*', '*.bin',
                  '*.pyc', '*.pyo', '*.o', '*.a', '*.so', '*.dylib',
                  '*.swp', '*.swo', '*~', '*.tmp', '*.bak', '*.orig', '*.rej',
                  '*.tar.gz', '*.zip')


def normalize(info):
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ''
    info.pax_headers = {}
    return info


with OUTPUT.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as zipped:
    with tarfile.open(fileobj=zipped, mode='w') as archive:
        for entry in ('.gitignore', 'README.md', 'core', 'integration', 'scripts'):
            path = ROOT / entry
            paths = [path] if path.is_file() else sorted(path.rglob('*'))
            for item in paths:
                relative = item.relative_to(ROOT)
                if (not item.is_file() or item.is_symlink() or item.name in {'oob-pir', 's7e4bench'}
                        or any(p in EXCLUDED for p in relative.parts)
                        or any(p.startswith('.') and p != '.gitignore' for p in relative.parts)
                        or any(fnmatch(item.name, pattern) for pattern in EXCLUDED_FILES)):
                    continue
                archive.add(item, arcname=str(Path('OOB') / relative), recursive=False, filter=normalize)
print(OUTPUT)
