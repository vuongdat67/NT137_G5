from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QApplication

from malware_analyzer.gui.main_window import MainWindow


def main() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyle("Fusion")

    style_path = Path("malware_analyzer/gui/assets/stylesheet.qss")
    if style_path.exists():
        try:
            app.setStyleSheet(style_path.read_text(encoding="utf-8"))
        except Exception:
            pass

    window = MainWindow()
    window.show()

    output = Path("docs/images/gui-scan.png")
    output.parent.mkdir(parents=True, exist_ok=True)

    def _capture() -> None:
        screen = app.primaryScreen()
        if screen is None:
            app.exit(1)
            return
        pixmap = screen.grabWindow(window.winId())
        ok = pixmap.save(str(output), "PNG")
        app.exit(0 if ok else 2)

    QTimer.singleShot(900, _capture)
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
