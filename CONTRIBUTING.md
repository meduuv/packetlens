# Contributing

Contributions are welcome when they improve correctness, portability, documentation or test coverage.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests -v
```

On Windows, activate the environment with `.venv\Scripts\activate`.

## Pull requests

Keep changes focused. Add or update tests when behavior changes, avoid unrelated formatting churn, and explain any compatibility impact in the pull request description.

For parser changes, include a minimal reproducible capture fixture or a clear description of the packet structure being handled.

## Reporting security issues

Do not include secrets, private packet captures or personal network data in public issues. Use sanitized examples whenever possible.
