"""ELLIOT unprivileged production GUI entry point."""

from __future__ import annotations

import logging
import os

from .controller import PardusController
from .model import PardusModel, WindowsModel
from .view import ElliotView


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    model = WindowsModel() if os.name == "nt" else PardusModel()
    view = ElliotView()
    controller = PardusController(model, view)
    controller.run()


if __name__ == "__main__":
    main()
