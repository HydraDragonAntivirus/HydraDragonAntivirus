#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import traceback
import webbrowser
import subprocess
import signal
from qasync import QEventLoop, asyncSlot

# Ensure the script's directory is the working directory
main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)

# Add the main directory to sys.path to allow absolute imports
if main_dir not in sys.path:
    sys.path.insert(0, main_dir)

from datetime import datetime, timedelta
from hydradragon.antivirus_scripts.antivirus import (
    logger,
    log_directory,
)
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QProgressBar,
                               QPushButton, QLabel, QTextEdit,
                               QFrame, QStackedWidget, QApplication, QButtonGroup)
from PySide6.QtCore import (Qt, QPropertyAnimation, QEasingCurve,
                            Signal, QParallelAnimationGroup, Property, QRect, QTimer)
from PySide6.QtGui import (QColor, QPainter, QBrush, QLinearGradient, QPen,
                           QPainterPath, QRadialGradient, QIcon, QPixmap)

# --- Import necessary functions from antivirus script ---
from hydradragon.antivirus_scripts.antivirus import (
    run_real_time_protection_async, # This MUST be an async generator
    reload_clamav_database,
    get_latest_clamav_def_time
)
# --- Import paths ---
from hydradragon.antivirus_scripts.path_and_variables import (
     freshclam_path,
    icon_path,
    hayabusa_path,
    WINDOW_TITLE,
    clamav_file_paths,
)

# --- Custom Hydra Icon Widget ---
class HydraIconWidget(QWidget):
    """A custom widget to draw the Hydra Dragon icon."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pixmap = None
        if os.path.exists(icon_path):
            self.pixmap = QPixmap(icon_path)
        else:
            logger.error(f"Sidebar icon not found at {icon_path}. Drawing fallback.")

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        if self.pixmap and not self.pixmap.isNull():
            painter.drawPixmap(self.rect(), self.pixmap)
        else:
            primary_color = QColor("#88C0D0")
            shadow_color = QColor("#4C566A")
            path = QPainterPath()
            # your path drawing...
            painter.setPen(QPen(primary_color, 3))
            painter.setBrush(shadow_color)
            painter.drawPath(path)

        painter.end()

# --- Custom Shield Widget for Status ---
class ShieldWidget(QWidget):
    """A custom widget to draw an animated status shield with a glowing effect."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAutoFillBackground(True)
        self.is_protected = True
        self._glow_opacity = 0.0
        self._check_progress = 1.0
        self._scale_factor = 1.0
        self.setMinimumSize(250, 250)

        # Load the hydra image for the protected state
        self.hydra_pixmap = None
        if os.path.exists(icon_path):
            self.hydra_pixmap = QPixmap(icon_path)
        else:
            logger.error(f"Shield icon not found at {icon_path}. Will use fallback drawing.")


        # Animation for the icon appearing/disappearing
        self.check_animation = QPropertyAnimation(self, b"check_progress")
        self.check_animation.setDuration(500)
        self.check_animation.setEasingCurve(QEasingCurve.Type.InOutCubic)

        # Animation for the background glow
        self.glow_animation = QPropertyAnimation(self, b"glow_opacity")
        self.glow_animation.setDuration(2500)
        self.glow_animation.setLoopCount(-1)
        self.glow_animation.setStartValue(0.2)
        self.glow_animation.setKeyValueAt(0.5, 0.7)
        self.glow_animation.setEndValue(0.2)
        self.glow_animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        self.glow_animation.start()

        # Breathing animation for the shield
        self.breathe_animation = QPropertyAnimation(self, b"scale_factor")
        self.breathe_animation.setDuration(5000)
        self.breathe_animation.setLoopCount(-1)
        self.breathe_animation.setStartValue(1.0)
        self.breathe_animation.setKeyValueAt(0.5, 1.05)
        self.breathe_animation.setEndValue(1.0)
        self.breathe_animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        self.breathe_animation.start()

    # --- Getter/Setter for check_progress ---
    def get_check_progress(self):
        return self._check_progress

    def set_check_progress(self, value):
        self._check_progress = value
        self.update()

    # --- Getter/Setter for glow_opacity ---
    def get_glow_opacity(self):
        return self._glow_opacity

    def set_glow_opacity(self, value):
        self._glow_opacity = value
        self.update()

    # --- Getter/Setter for scale_factor ---
    def get_scale_factor(self):
        return self._scale_factor

    def set_scale_factor(self, value):
        self._scale_factor = value
        self.update()

    # --- Qt Properties for Animation ---
    check_progress = Property(float, get_check_progress, set_check_progress)
    glow_opacity = Property(float, get_glow_opacity, set_glow_opacity)
    scale_factor = Property(float, get_scale_factor, set_scale_factor)

    def set_status(self, is_protected):
        if self.is_protected != is_protected:
            self.is_protected = is_protected
            self.check_animation.setStartValue(0.0)
            self.check_animation.setEndValue(1.0)
            self.check_animation.start()
            self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        side = min(self.width(), self.height())
        painter.translate(self.width() / 2, self.height() / 2)
        painter.scale(self._scale_factor, self._scale_factor)
        painter.scale(side / 220.0, side / 220.0)

        glow_color = QColor(0, 255, 127) if self.is_protected else QColor(255, 80, 80)
        gradient = QRadialGradient(0, 0, 110)
        glow_color.setAlphaF(self._glow_opacity)
        gradient.setColorAt(0.5, glow_color)
        glow_color.setAlphaF(0)
        gradient.setColorAt(1.0, glow_color)
        painter.setBrush(QBrush(gradient))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(-110, -110, 220, 220)

        path = QPainterPath()
        path.moveTo(0, -90)
        path.cubicTo(80, -80, 80, 0, 80, 0)
        path.lineTo(80, 40)
        path.quadTo(80, 90, 0, 100)
        path.quadTo(-80, 90, -80, 40)
        path.lineTo(-80, 0)
        path.cubicTo(-80, -80, 0, -90, 0, -90)

        shield_gradient = QLinearGradient(0, -90, 0, 100)
        shield_gradient.setColorAt(0, QColor("#434C5E"))
        shield_gradient.setColorAt(1, QColor("#3B4252"))
        painter.fillPath(path, QBrush(shield_gradient))

        progress = self._check_progress
        if self.is_protected:
            if self.hydra_pixmap and not self.hydra_pixmap.isNull():
                painter.setOpacity(progress)
                pixmap_rect = QRect(-75, -85, 150, 150)
                painter.drawPixmap(pixmap_rect, self.hydra_pixmap)
                painter.setOpacity(1.0)
        else:
            painter.setPen(QPen(QColor("white"), 14, Qt.PenStyle.SolidLine,
                                Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawLine(int(-35 * progress), int(-35 * progress), int(35 * progress), int(35 * progress))
            painter.drawLine(int(35 * progress), int(-35 * progress), int(-35 * progress), int(35 * progress))

        painter.end()

class AntivirusApp(QWidget):
    # Signals for safe cross-thread UI marshalling
    log_signal = Signal(str)
    status_signal = Signal(bool)   # True => protected, False => busy
    progress_signal = Signal(float)  # progress 0.0..1.0, optional usage

    def __init__(self):
        super().__init__()

        # state
        self.active_tasks = set()
        self.log_outputs = []  # list of QTextEdit widgets for each page
        self.animation_group = QParallelAnimationGroup()
        self.defs_label = None

        # wire signals
        self.log_signal.connect(self._append_log_output_slot)
        self.status_signal.connect(self._on_status_signal)
        self.progress_signal.connect(self._on_progress_signal)

        # apply stylesheet and build UI
        self.apply_extreme_stylesheet()

        # Run startup tasks after UI shown
        QTimer.singleShot(0, self.run_startup_tasks)

    # ---------------------------
    # Signal handlers / UI marshalling
    # ---------------------------
    def _append_log_output_slot(self, text: str):
        """Append log messages to the current log widget (runs on Qt thread)."""
        try:
            current_page_index = self.main_stack.currentIndex()
            if 0 <= current_page_index < len(self.log_outputs):
                log_widget = self.log_outputs[current_page_index]
                if log_widget is None or not isinstance(log_widget, QTextEdit):
                    return
                log_widget.append(text)
                # auto-scroll if near bottom
                scrollbar = log_widget.verticalScrollBar()
                at_bottom = scrollbar.value() >= (scrollbar.maximum() - 20)
                if at_bottom:
                    scrollbar.setValue(scrollbar.maximum())
        except Exception:
            logger.exception("Error in _append_log_output_slot")


    def _on_status_signal(self, is_protected: bool):
        """Slot to update shield & status text; always runs on the Qt thread."""
        try:
            if hasattr(self, 'shield_widget') and self.shield_widget:
                self.shield_widget.set_status(bool(is_protected))
            if hasattr(self, 'status_text') and self.status_text:
                self.status_text.setText(
                    "System protected!" if is_protected else "System busy..."
                )
                self.status_text.setObjectName(
                    "page_subtitle" if is_protected else "page_subtitle_busy"
                )
                self.status_text.setStyle(self.style())
        except Exception:
            logger.exception("Error in _on_status_signal")


    def _on_progress_signal(self, value: float):
        """Receive progress updates (0.0..1.0) and update shield / progress bar."""
        try:
            if hasattr(self, 'shield_widget') and self.shield_widget:
                self.shield_widget.set_check_progress(float(value))
            if hasattr(self, 'defs_progress_bar') and isinstance(self.defs_progress_bar, QProgressBar):
                v = int(max(0, min(100, value * 100)))
                self.defs_progress_bar.setValue(v)
        except Exception:
            logger.exception("Error in _on_progress_signal")


    # ---------------------------
    # Logging wrapper
    # ---------------------------
    def append_log_output(self, text: str):
        """Thread-safe/log-safe way to append logs to UI via signal."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            formatted = f"{timestamp} {text}"
            self.log_signal.emit(formatted)
            logger.info(text)
        except Exception:
            logger.exception("append_log_output failed")

    # ---------------------------
    # Stylesheet
    # ---------------------------
    def apply_extreme_stylesheet(self):
        stylesheet = """
            QWidget { background-color: #2E3440; color: #D8DEE9; font-family: 'Segoe UI', Arial; font-size: 14px; }
            QTextEdit { background-color: #3B4252; border: 2px solid #4C566A; border-radius: 10px; padding: 12px; color: #ECEFF4; font-family: 'JetBrains Mono', monospace; font-size: 13px; }
            QTextEdit:focus { border: 2px solid #88C0D0; }
            #sidebar { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #2E3440, stop:1 #232831); max-width:240px; border-right:1px solid #4C566A; }
            #logo { color: #88C0D0; font-size: 32px; font-weight: bold; letter-spacing:2px; }
            #nav_button { background-color: transparent; border: none; color:#D8DEE9; padding:14px 16px; text-align:left; border-radius:8px; font-size:13px; font-weight:500; margin:2px 8px; }
            #nav_button:hover { background-color: #434C5E; color: #ECEFF4; }
            #nav_button:checked { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #88C0D0, stop:1 #81A1C1); color:#2E3440; font-weight:bold; }
            #page_title { font-size: 32px; font-weight: 300; color: #ECEFF4; padding-bottom: 20px; letter-spacing:1px; }
            #page_subtitle { font-size: 18px; color: #A3BE8C; font-weight: 500; }
            #page_subtitle_busy { font-size: 18px; color: #EBCB8B; font-weight: 500; }
            #version_label { font-size: 13px; color: #81A1C1; font-weight: 400; }
            #action_button { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #5E81AC,stop:1 #5273A0); color:#ECEFF4; border-radius:10px; padding:14px 24px; font-size:14px; font-weight:bold; border:none; min-width:180px; }
            #action_button:hover { background: qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #81A1C1,stop:1 #6B8DB8); }
            #action_button:pressed { background: #4C6A94; }
            #action_button:disabled { background: #4C566A; color: #8F9AA8; }
            #status_card { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #3B4252, stop:1 #343D4C); border:2px solid #4C566A; border-radius:12px; padding:15px; }
            QProgressBar { border:2px solid #4C566A; border-radius:8px; text-align:center; background-color:#3B4252; color:#ECEFF4; height:10px; }
            QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #88C0D0, stop:0.5 #81A1C1, stop:1 #5E81AC); border-radius:6px; margin:1px; }
        """
        self.setStyleSheet(stylesheet)

    # ---------------------------
    # Task runner utilities
    # ---------------------------
    def _update_ui_for_task_start(self, task_name: str):
        """Update UI when a task starts."""
        try:
            self.append_log_output(f"[*] Task '{task_name}' started.")
            self.status_signal.emit(False)
            if hasattr(self, 'task_buttons') and task_name in self.task_buttons:
                try:
                    self.task_buttons[task_name].setEnabled(False)
                except Exception:
                    logger.exception("Failed to disable task button")
        except Exception:
            logger.exception("_update_ui_for_task_start failed")


    def _update_ui_for_task_end(self, task_name: str):
        """Update UI when a task ends."""
        try:
            self.append_log_output(f"[+] Task '{task_name}' finished.")
            # Only set shield to protected if no active tasks remain
            if not self.active_tasks:
                self.status_signal.emit(True)

            if hasattr(self, 'task_buttons') and task_name in self.task_buttons:
                try:
                    self.task_buttons[task_name].setEnabled(True)
                except Exception:
                    logger.exception("Failed to enable task button")

            if task_name == 'update_definitions' and self.defs_label:
                try:
                    self.defs_label.setText(get_latest_clamav_def_time())
                except Exception:
                    logger.exception("Failed to update defs_label text")
        except Exception:
            logger.exception("_update_ui_for_task_end failed")


    async def run_task(self, task_name: str, coro_or_func, *args, is_async: bool = True):
        """
        Run an async coroutine, async generator, or blocking function on a background thread.
        Handles UI updates safely via Qt signals and QTimer.
        """
        if task_name in self.active_tasks:
            self.append_log_output(f"[*] Task '{task_name}' already running.")
            return

        self.active_tasks.add(task_name)
        QTimer.singleShot(0, lambda: self._update_ui_for_task_start(task_name))

        try:
            if is_async:
                result = coro_or_func(*args)
                if hasattr(result, "__anext__"):  # Async generator
                    async for item in result:
                        if item:
                            self.append_log_output(str(item))
                else:
                    msg = await result
                    if msg:
                        self.append_log_output(str(msg))
            else:
                await asyncio.to_thread(coro_or_func, *args)
        except asyncio.CancelledError:
            self.append_log_output(f"[!] Task '{task_name}' was cancelled.")
            logger.info(f"Task {task_name} cancelled.")
        except Exception:
            self.append_log_output(f"[!] Error in task '{task_name}': {traceback.format_exc()}")
            logger.exception(f"Exception in task {task_name}")
        finally:
            if task_name in self.active_tasks:
                self.active_tasks.remove(task_name)
            QTimer.singleShot(0, lambda: self._update_ui_for_task_end(task_name))

    # ---------------------------
    # Real-Time Protection (Async)
    # ---------------------------
    async def _run_real_time_protection_task(self):
        """Async wrapper for real-time protection generator."""
        self.append_log_output("[*] Real-time protection starting...")
        try:
            gen = run_real_time_protection_async()
            if hasattr(gen, "__anext__"):  # Async generator
                async for msg in gen:
                    if msg:
                        self.append_log_output(str(msg))
            else:  # fallback if normal coroutine
                result = await gen
                if result:
                    self.append_log_output(str(result))
            self.append_log_output("[+] Real-time protection completed.")
        except asyncio.CancelledError:
            self.append_log_output("[!] Real-time protection task cancelled.")
        except Exception:
            self.append_log_output(f"[!] Real-time protection error: {traceback.format_exc()}")
            logger.exception("Unhandled exception in real-time protection")

    def _update_definitions_sync(self):
        """Blocking freshclam update, run inside a thread."""
        self.append_log_output("[*] Checking virus definitions...")
        try:
            if not os.path.exists(freshclam_path):
                self.append_log_output(f"[!] freshclam not found at '{freshclam_path}'")
                return False

            needs_update = any(
                not os.path.exists(fp) or
                (datetime.now() - datetime.fromtimestamp(os.path.getmtime(fp))) > timedelta(hours=12)
                for fp in clamav_file_paths
            )

            if needs_update:
                self.append_log_output("[*] Running freshclam update...")
                proc = subprocess.Popen([freshclam_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = proc.communicate()

                if stdout:
                    for line in stdout.splitlines():
                        self.append_log_output(line)
                if stderr:
                    for line in stderr.splitlines():
                        self.append_log_output(f"[!] {line}")

                if proc.returncode == 0:
                    reload_clamav_database()
                    self.append_log_output("[+] Virus definitions updated successfully.")
                    return True
                else:
                    self.append_log_output(f"[!] freshclam failed with exit code {proc.returncode}")
                    return False
            else:
                self.append_log_output("[*] Definitions are already up to date.")
                return True
        except Exception:
            self.append_log_output(f"[!] Definition update error: {traceback.format_exc()}")
            logger.exception("Definition update failed")
            return False

    def _update_hayabusa_rules_sync(self):
        self.append_log_output("[*] Updating Hayabusa rules...")
        try:
            if not os.path.exists(hayabusa_path):
                self.append_log_output(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return False

            cmd = [hayabusa_path, "update-rules"]
            self.append_log_output(f"[*] Running command: {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="ignore"
            )

            stdout, stderr = process.communicate()
            if stdout: self.append_log_output(f"[Hayabusa Update] {stdout.strip()}")
            if stderr: self.append_log_output(f"[Hayabusa Update ERR] {stderr.strip()}")

            if process.returncode == 0:
                self.append_log_output("[+] Hayabusa rules update completed successfully!")
                return True
            else:
                self.append_log_output(f"[!] Hayabusa rules update failed (code {process.returncode})")
                return False
        except Exception:
            self.append_log_output(f"[!] Error updating Hayabusa rules: {traceback.format_exc()}")
            logger.exception("Exception during Hayabusa rule update")
            return False

    # ---------------------------
    # Button handlers (asyncSlots)
    # ---------------------------
    @asyncSlot()
    async def on_update_definitions_clicked(self):
        await self.run_task('update_definitions', self._update_definitions_sync, is_async=False)

    @asyncSlot()
    async def on_update_hayabusa_rules_clicked(self):
        await self.run_task('update_hayabusa_rules', self._update_hayabusa_rules_sync, is_async=False)


    # ---------------------------
    # Startup Tasks (Non-blocking)
    # ---------------------------
    async def run_startup_tasks(self):
        """Launch startup tasks safely after UI is shown."""
        self.append_log_output("[*] Initializing startup tasks...")

        # Schedule real-time protection safely
        asyncio.create_task(self.run_task(
            'real_time_protection',
            self._run_real_time_protection_task,
        ))

        self.append_log_output("[*] Startup tasks launched.")

    # ---------------------------
    # UI Pages / layout creation (kept mostly as before)
    # ---------------------------
    def create_status_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(30)

        main_area = QHBoxLayout()
        main_area.setSpacing(40)

        self.shield_widget = ShieldWidget()
        main_area.addWidget(self.shield_widget, 2)

        status_vbox = QVBoxLayout()
        status_vbox.addStretch()

        title = QLabel("System Status")
        title.setObjectName("page_title")
        self.status_text = QLabel("Initializing...")
        self.status_text.setObjectName("page_subtitle_busy")

        version_label = QLabel(WINDOW_TITLE)
        version_label.setObjectName("version_label")

        self.defs_label = QLabel(get_latest_clamav_def_time())
        self.defs_label.setObjectName("version_label")

        status_vbox.addWidget(title)
        status_vbox.addWidget(self.status_text)
        status_vbox.addSpacing(30)
        status_vbox.addWidget(version_label)
        status_vbox.addWidget(self.defs_label)
        status_vbox.addStretch()

        main_area.addLayout(status_vbox, 3)
        layout.addLayout(main_area)
        layout.addStretch()

        self.log_outputs.append(None)
        return page

    def create_task_page(self, title_text, main_task_name, main_button_text, additional_tasks=None):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        if not hasattr(self, 'task_buttons'):
            self.task_buttons = {}

        header_layout = QHBoxLayout()
        title = QLabel(title_text)
        title.setObjectName("page_title")
        header_layout.addWidget(title)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        button_container = QHBoxLayout()
        button_container.setSpacing(15)

        main_button = QPushButton(main_button_text)
        main_button.setObjectName("action_button")
        self.task_buttons[main_task_name] = main_button

        if main_task_name == 'update_definitions':
            main_button.clicked.connect(self.on_update_definitions_clicked)
        elif main_task_name == 'update_hayabusa_rules':
            main_button.clicked.connect(self.on_update_hayabusa_rules_clicked)
        else:
            main_button.setEnabled(False)

        button_container.addWidget(main_button)

        if additional_tasks:
            for btn_text, task_info in additional_tasks.items():
                task_name = task_info['name']
                is_async = task_info['is_async']
                func = task_info['func']

                extra_btn = QPushButton(btn_text)
                extra_btn.setObjectName("action_button")
                self.task_buttons[task_name] = extra_btn

                extra_btn.clicked.connect(
                    lambda checked=False, tn=task_name, f=func, ia=is_async:
                    asyncio.create_task(self.run_task(tn, f, is_async=ia))
                )
                button_container.addWidget(extra_btn)

        button_container.addStretch()
        layout.addLayout(button_container)

        log_output = QTextEdit(f"{title_text} logs will appear here...")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)

        self.log_outputs.append(log_output)
        return page

    def create_about_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(25)

        title = QLabel("About HydraDragon")
        title.setObjectName("page_title")
        layout.addWidget(title)

        about_text = QLabel("HydraDragon Antivirus - Open Source Antivirus with Advanced Real-Time Protection.")
        about_text.setWordWrap(True)
        about_text.setStyleSheet("font-size: 15px; line-height: 1.6;")
        layout.addWidget(about_text)

        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(15)

        github_button = QPushButton("View on GitHub")
        github_button.setObjectName("action_button")
        github_button.clicked.connect(lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus"))
        buttons_layout.addWidget(github_button)

        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
        layout.addStretch()

        self.log_outputs.append(None)
        return page

    def create_main_content(self):
        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self.create_status_page())

        update_additional_tasks = {
            "Update Hayabusa Rules": {
                'name': 'update_hayabusa_rules',
                'is_async': False,
                'func': self._update_hayabusa_rules_sync
            }
        }

        self.main_stack.addWidget(self.create_task_page(
            "Updates",
            main_task_name='update_definitions',
            main_button_text="Update ClamAV Definitions",
            additional_tasks=update_additional_tasks
        ))

        self.main_stack.addWidget(self.create_about_page())
        return self.main_stack

    # helper factory so handler does not return a Task (prevents double-scheduling)
    def _make_nav_handler(self, idx: int):
        def _handler(checked=False):
            # schedule the coroutine but DO NOT return the created Task object
            asyncio.create_task(self.switch_page_with_animation(idx))
            return None
        return _handler


    def create_sidebar(self):
        sidebar_frame = QFrame()
        sidebar_frame.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar_frame)
        sidebar_layout.setContentsMargins(15, 25, 15, 25)
        sidebar_layout.setSpacing(8)

        logo_area = QHBoxLayout()
        logo_area.setSpacing(12)

        # HydraIconWidget should exist in your file
        try:
            icon_widget = HydraIconWidget(sidebar_frame)
            icon_widget.setFixedSize(40, 40)
        except Exception:
            icon_widget = QLabel("H")  # fallback

        logo_label = QLabel("HYDRA")
        logo_label.setObjectName("logo")

        logo_area.addWidget(icon_widget)
        logo_area.addWidget(logo_label)
        logo_area.addStretch()

        sidebar_layout.addLayout(logo_area)
        sidebar_layout.addSpacing(30)

        # Use Unicode escape sequences instead of literal emoji characters
        house = '\U0001F3E0'   # 🏠
        sync = '\u21BB'        # ↻ (clockwise open circle arrow)
        info = '\u2139'        # ℹ (information source)
        nav_buttons = [(house, "Status"), (sync, "Updates"), (info, "About")]

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        for i, (icon, name) in enumerate(nav_buttons):
            button = QPushButton(f"{icon}  {name}")
            button.setCheckable(True)
            button.setObjectName("nav_button")
            # use handler factory so slot does not return a Task
            button.clicked.connect(self._make_nav_handler(i))
            sidebar_layout.addWidget(button)
            self.nav_group.addButton(button, i)

        first_button = self.nav_group.button(0)
        if first_button:
            first_button.setChecked(True)

        sidebar_layout.addStretch()

        version_label_side = QLabel(f"Version: {WINDOW_TITLE.split('v')[-1] if 'v' in WINDOW_TITLE else 'N/A'}")
        version_label_side.setStyleSheet("color: #6A7384; font-size: 11px; padding: 0 10px;")
        sidebar_layout.addWidget(version_label_side)

        return sidebar_frame

    def setup_ui_fast(self):
        """Create widgets and layout — no heavy I/O or icon loads."""
        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(1100, 800)
        self.resize(1400, 900)

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self.create_sidebar())
        main_layout.addWidget(self.create_main_content(), 1)

    async def finish_ui_setup(self):
        """Perform heavy UI initialization safely after the event loop starts."""
        try:
            # Let the window render first
            await asyncio.sleep(0)

            # --- Load window icon in background ---
            if os.path.exists(icon_path):
                try:
                    # Load QIcon in a thread (disk I/O)
                    icon = await asyncio.to_thread(QIcon, icon_path)
                except Exception:
                    logger.exception("Failed to load window icon in background")
                    icon = None

                if icon:
                    # Apply icon on main thread
                    try:
                        self.setWindowIcon(icon)
                        logger.debug(f"Window icon applied from: {icon_path}")
                    except Exception:
                        logger.exception("Failed to apply window icon on main thread")
            else:
                logger.debug(f"Icon file not found at: {icon_path}")

            # --- Load HydraIconWidget resources in background ---
            try:
                icon_widget = getattr(self, "icon_widget", None)
                if icon_widget and hasattr(icon_widget, "load_resources"):
                    await asyncio.to_thread(icon_widget.load_resources)
                    logger.debug("HydraIconWidget resources loaded")
            except Exception:
                logger.exception("Error loading HydraIconWidget resources")

            logger.info("UI setup finalized (icons, resources, etc.)")

        except Exception:
            logger.exception("Unhandled exception in finish_ui_setup")

    # ---------------------------
    # Page switching animations
    # ---------------------------
    @asyncSlot(int)
    async def switch_page_with_animation(self, index: int):
        if (self.animation_group.state() == QParallelAnimationGroup.State.Running or
                self.main_stack.currentIndex() == index):
            return

        current_widget = self.main_stack.currentWidget()
        next_widget = self.main_stack.widget(index)

        current_opacity_anim = QPropertyAnimation(current_widget, b"windowOpacity")
        current_opacity_anim.setDuration(250)
        current_opacity_anim.setStartValue(1.0)
        current_opacity_anim.setEndValue(0.0)
        current_opacity_anim.finished.connect(current_widget.hide)

        next_opacity_anim = QPropertyAnimation(next_widget, b"windowOpacity")
        next_opacity_anim.setDuration(250)
        next_opacity_anim.setStartValue(0.0)
        next_opacity_anim.setEndValue(1.0)

        next_widget.setWindowOpacity(0.0)
        self.main_stack.setCurrentIndex(index)
        next_widget.show()
        next_widget.raise_()

        self.animation_group = QParallelAnimationGroup()
        self.animation_group.addAnimation(current_opacity_anim)
        self.animation_group.addAnimation(next_opacity_anim)
        self.animation_group.finished.connect(self._on_animation_finished)
        self.animation_group.start()

    def _on_animation_finished(self):
        current_widget = self.main_stack.currentWidget()
        if current_widget:
            current_widget.setWindowOpacity(1.0)

    # ---------------------------
    # Window event handlers
    # ---------------------------
    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.append_log_output("[*] Application minimized (window hidden)")

async def main():
    """Unified async main entry point for HydraDragon Engine (PySide6 + qasync)."""
    app = None
    loop = None
    exit_code = 0

    try:
        os.makedirs(log_directory, exist_ok=True)
    except Exception as e:
        print(f"Error creating log directory {log_directory}: {e}", file=sys.stderr)

    try:
        # QApplication first
        app = QApplication(sys.argv)

        # qasync event loop
        loop = QEventLoop(app)
        asyncio.set_event_loop(loop)

        # Main window
        window = AntivirusApp()
        window.setup_ui_fast()
        window.show()
        asyncio.create_task(window.finish_ui_setup())

        # OS signals
        def signal_handler(signum, frame):
            logger.info(f"Signal {signum} received, shutting down...")
            if loop and loop.is_running():
                loop.stop()

        signal.signal(signal.SIGINT, signal_handler)
        try:
            signal.signal(signal.SIGTERM, signal_handler)
        except AttributeError:
            pass

        logger.info("Main window shown, event loop running...")
        await asyncio.Event().wait()  # Wait forever until signal/loop stop

    except Exception:
        logger.exception("Critical error in main()")
        exit_code = 1
    finally:
        logger.info("Cleaning up application...")

        # Proper shutdown sequence
        if app:
            try:
                app.quit()  # Quit Qt application
            except Exception:
                pass
        if loop:
            try:
                loop.close()  # Close qasync loop explicitly
            except Exception:
                pass

    logger.info(f"Application exited with code {exit_code}")
    return exit_code
