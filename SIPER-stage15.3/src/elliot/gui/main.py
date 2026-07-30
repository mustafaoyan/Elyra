"""ELLIOT unprivileged production GUI entry point."""

from __future__ import annotations

import logging

from .controller import PardusController
from .model import PardusModel
from .view import PardusView


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    model = PardusModel()
    view = PardusView()
    controller = PardusController(model, view)
    controller.run()


if __name__ == "__main__":
    main()
