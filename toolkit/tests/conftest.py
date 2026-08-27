"""Shared pytest fixtures/config for the VANGUARD toolkit test suite.

The toolkit modules (database.py, ai_analyst.py, threat_sync.py,
pdf_reporter.py, main.py) use flat, non-package `import database` /
`import ai_analyst` style imports (they're designed to run as a plain
script directory via `python3 main.py ...`, not an installed package).
This conftest inserts the toolkit/ directory onto sys.path so `import
database` etc. resolve the same way inside pytest as they do when
main.py is run directly.

No test in this suite ever opens a real SQLite file or makes a real
outbound HTTP/LLM call -- every external dependency (database
connections, `requests.get`, the Anthropic/OpenAI SDKs) is mocked at
the point ai_analyst.py / threat_sync.py touch it, per the task's
"don't hit real APIs or DBs" requirement.
"""

import sys
from pathlib import Path

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
if str(TOOLKIT_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLKIT_ROOT))
