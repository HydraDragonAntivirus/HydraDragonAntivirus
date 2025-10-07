#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import threading
from logly import logger
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QGraphicsOpacityEffect,
    QApplication,
)
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, Signal, QObject

script_dir = os.path.dirname(os.path.abspath(__file__))
log_directory = os.path.join(script_dir, "log")
os.makedirs(log_directory, exist_ok=True)
application_log_file = os.path.join(log_directory, "antivirus.log")

logger.add("console")
logger.add(
    application_log_file,
    rotation="daily",
    retention=7,
    date_enabled=True,
    async_write=True,
)

logger.configure(level="DEBUG", color=True, show_time=True, json=False)


# Global tracking variables
class AlertTracker(QObject):
    """Thread-safe tracker that only counts critical alerts"""
    critical_alert_signal = Signal(str, str)  # title, message

    def __init__(self):
        super().__init__()
        self.critical_count = 0
        self.lock = threading.Lock()
        self.is_gui_mode = False
        self.gui_app = None

    def increment_critical(self):
        with self.lock:
            self.critical_count += 1
            return self.critical_count

    def get_counts(self):
        """Return the current number of critical alerts (single int)."""
        with self.lock:
            return self.critical_count

# Global instance
alert_tracker = AlertTracker()


def detect_script_name():
    """Detect which script is running"""
    try:
        script_name = os.path.basename(sys.argv[0])
        return script_name
    except Exception:
        return "unknown"


def is_gui_available():
    """Check if GUI mode is available"""
    try:
        app = QApplication.instance()
        return app is not None
    except Exception:
        return False


class CriticalAlertPopup(QWidget):
    """Modern critical alert popup notification"""

    def __init__(self, title, message, level="CRITICAL", parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_DeleteOnClose)

        self.level = level
        self.setup_ui(title, message)
        self.setup_animations()
        self.position_popup()

    def setup_ui(self, title, message):
        """Setup the notification UI"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)

        container = QWidget()
        container.setObjectName("alert_container")
        container_layout = QVBoxLayout(container)
        container_layout.setContentsMargins(20, 20, 20, 20)
        container_layout.setSpacing(15)

        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        icon_label = QLabel()
        icon_label.setObjectName("alert_icon")
        icon_label.setFixedSize(48, 48)
        icon_label.setAlignment(Qt.AlignCenter)
        icon_label.setText("⚠")
        icon_label.setStyleSheet("font-size: 36px; color: #BF616A;")

        header_layout.addWidget(icon_label)

        title_container = QVBoxLayout()
        title_container.setSpacing(5)

        title_label = QLabel(title)
        title_label.setObjectName("alert_title")
        title_label.setWordWrap(True)
        title_container.addWidget(title_label)

        level_label = QLabel(self.level)
        level_label.setObjectName("alert_level")
        title_container.addWidget(level_label)

        header_layout.addLayout(title_container, 1)

        close_btn = QPushButton("×")
        close_btn.setObjectName("close_button")
        close_btn.setFixedSize(32, 32)
        close_btn.clicked.connect(self.close_animation)
        header_layout.addWidget(close_btn, 0, Qt.AlignTop)

        container_layout.addLayout(header_layout)

        message_label = QLabel(message)
        message_label.setObjectName("alert_message")
        message_label.setWordWrap(True)
        message_label.setMaximumWidth(400)
        container_layout.addWidget(message_label)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        button_layout.addStretch()

        dismiss_btn = QPushButton("Dismiss")
        dismiss_btn.setObjectName("dismiss_button")
        dismiss_btn.setMinimumWidth(100)
        dismiss_btn.clicked.connect(self.close_animation)

        details_btn = QPushButton("View Details")
        details_btn.setObjectName("details_button")
        details_btn.setMinimumWidth(100)
        details_btn.clicked.connect(self.show_details)

        button_layout.addWidget(details_btn)
        button_layout.addWidget(dismiss_btn)

        container_layout.addLayout(button_layout)

        main_layout.addWidget(container)

        self.apply_stylesheet()

    def apply_stylesheet(self):
        """Apply modern stylesheet to the alert"""
        stylesheet = """
            #alert_container {
                background-color: #2E3440;
                border: 2px solid #BF616A;
                border-radius: 12px;
                min-width: 450px;
                max-width: 500px;
            }
            
            #alert_title {
                color: #ECEFF4;
                font-size: 18px;
                font-weight: bold;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            #alert_level {
                color: #BF616A;
                font-size: 12px;
                font-weight: bold;
                letter-spacing: 1px;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            #alert_message {
                color: #D8DEE9;
                font-size: 14px;
                line-height: 1.6;
                font-family: 'Segoe UI', Arial, sans-serif;
                padding: 10px;
                background-color: #3B4252;
                border-radius: 6px;
                border-left: 3px solid #BF616A;
            }
            
            #close_button {
                background-color: transparent;
                color: #D8DEE9;
                border: none;
                font-size: 28px;
                font-weight: bold;
                border-radius: 16px;
            }
            
            #close_button:hover {
                background-color: #BF616A;
                color: #ECEFF4;
            }
            
            #dismiss_button {
                background-color: #4C566A;
                color: #ECEFF4;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 13px;
                font-weight: bold;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            #dismiss_button:hover {
                background-color: #5E6A7A;
            }
            
            #details_button {
                background-color: #5E81AC;
                color: #ECEFF4;
                border: none;
                border-radius: 6px;
                padding: 10px 20px;
                font-size: 13px;
                font-weight: bold;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            #details_button:hover {
                background-color: #81A1C1;
            }
        """
        self.setStyleSheet(stylesheet)

    def setup_animations(self):
        """Setup fade in/out animations"""
        self.opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self.opacity_effect)

        self.fade_in = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_in.setDuration(300)
        self.fade_in.setStartValue(0.0)
        self.fade_in.setEndValue(1.0)
        self.fade_in.setEasingCurve(QEasingCurve.OutCubic)

        self.fade_out = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.fade_out.setDuration(250)
        self.fade_out.setStartValue(1.0)
        self.fade_out.setEndValue(0.0)
        self.fade_out.setEasingCurve(QEasingCurve.InCubic)
        self.fade_out.finished.connect(self.close)

    def position_popup(self):
        """Position popup at bottom-right of screen"""
        screen = QApplication.primaryScreen().geometry()
        self.adjustSize()

        x = screen.width() - self.width() - 30
        y = screen.height() - self.height() - 50

        self.move(x, y)

    def show_details(self):
        """Handle details button click"""
        logger.info("User requested alert details")

    def close_animation(self):
        """Animate close"""
        self.fade_out.start()

    def showEvent(self, event):
        """Override show event to start fade in animation"""
        super().showEvent(event)
        self.fade_in.start()


def show_critical_alert(title, message, level="CRITICAL"):
    """Show critical alert popup - only if GUI is available"""
    if is_gui_available():
        try:
            alert = CriticalAlertPopup(title, message, level)
            alert.show()
            return alert
        except Exception as e:
            logger.error(f"Failed to show GUI alert: {str(e)}")
            return None
    return None


def alert_on_critical(record):
    """Show popup alert for critical level logs only"""
    if record.get("level") == "CRITICAL":
        # Increment critical count
        count = alert_tracker.increment_critical()

        # Detect script
        script_name = detect_script_name()

        title = "Critical Security Alert"
        message = record.get("message", "")

        # Add script information to message
        message = f"[{script_name}] {message}"

        # Extract additional context if available
        if "extra" in record:
            context_parts = [f"{k}: {v}" for k, v in record["extra"].items()]
            if context_parts:
                message += "\n\n" + "\n".join(context_parts)

        # Add alert count
        message += f"\n\nTotal Critical Alerts: {count}"

        # Only show GUI popup if running in GUI mode
        if is_gui_available():
            show_critical_alert(title, message, "CRITICAL")

            # Update status cards if available
            try:
                app = QApplication.instance()
                if app and hasattr(app, "main_window"):
                    main_window = app.main_window
                    if hasattr(main_window, "threat_card"):
                        main_window.threat_card.value_label.setText(str(count))
            except Exception as e:
                logger.debug(f"Could not update status card: {str(e)}")


# Add callback to logger
callback_id = logger.add_callback(alert_on_critical)


def setup_gui_mode(main_window_instance):
    """Call this from your main GUI to enable GUI features"""
    alert_tracker.is_gui_mode = True
    app = QApplication.instance()
    if app:
        app.main_window = main_window_instance
        logger.info(f"GUI mode enabled for {detect_script_name()}")


def get_alert_counts():
    """Return the current critical alert count (int)."""
    return alert_tracker.get_counts()
