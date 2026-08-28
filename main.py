"""CLI shim — prefer `sentinel` after `pip install -e .`."""

from sentinel_cli.main import app

if __name__ == "__main__":
    app()
