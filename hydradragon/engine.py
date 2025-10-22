#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import threading
import traceback
import webbrowser
import subprocess
import asyncio
import csv
import aiofiles
from qasync import QEventLoop

# Ensure the script's directory is the working directory
main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)

# Add the main directory to sys.path to allow absolute imports
if main_dir not in sys.path:
    sys.path.insert(0, main_dir)

from datetime import datetime, timedelta
from hydra_logger import (
    logger,
    log_directory,
)
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QProgressBar,
                               QPushButton, QLabel, QTextEdit, QGraphicsDropShadowEffect,
                               QFrame, QStackedWidget, QApplication, QButtonGroup)
from PySide6.QtCore import (Qt, QPropertyAnimation, QEasingCurve, QThread,
                            Signal, QPoint, QParallelAnimationGroup, Property, QRect, QTimer)
from PySide6.QtGui import (QColor, QPainter, QBrush, QLinearGradient, QPen,
                           QPainterPath, QRadialGradient, QIcon, QPixmap)
from hydradragon.antivirus_scripts.antivirus import (
    run_real_time_protection_with_yield_async,
    reload_clamav_database,
    get_latest_clamav_def_time,
)
from hydradragon.antivirus_scripts.path_and_variables import (
    freshclam_path,
    icon_path,
    hayabusa_path,
    WINDOW_TITLE,
    clamav_file_paths,
)
from hydradragon.antivirus_scripts.notify_user import notify_user_hayabusa_critical

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
            path.moveTo(0, 20)
            path.quadTo(15, 0, 30, 20)
            path.quadTo(15, 10, 0, 20)
            path.moveTo(5, 15)
            path.cubicTo(-20, 0, -10, -25, 0, -20)
            path.quadTo(-5, -18, 5, 15)
            path.moveTo(25, 15)
            path.cubicTo(50, 0, 40, -25, 30, -20)
            path.quadTo(35, -18, 25, 15)
            path.moveTo(15, 10)
            path.cubicTo(10, -20, 20, -20, 15, 10)
            painter.setPen(QPen(primary_color, 3))
            painter.setBrush(shadow_color)
            painter.drawPath(path)


# --- Advanced Shield Widget with Particle Effects ---
class ShieldWidget(QWidget):
    """Enhanced shield widget with advanced animations and particle effects."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAutoFillBackground(True)
        self.is_protected = True
        self._glow_opacity = 0.0
        self._check_progress = 1.0
        self._scale_factor = 1.0
        self._rotation_angle = 0.0
        self._pulse_intensity = 1.0
        self.setMinimumSize(280, 280)

        self.hydra_pixmap = None
        if os.path.exists(icon_path):
            self.hydra_pixmap = QPixmap(icon_path)
        else:
            logger.error(f"Shield icon not found at {icon_path}. Will use fallback drawing.")

        # Check animation
        self.check_animation = QPropertyAnimation(self, b"check_progress")
        self.check_animation.setDuration(600)
        self.check_animation.setEasingCurve(QEasingCurve.Type.OutElastic)

        # Glow animation
        self.glow_animation = QPropertyAnimation(self, b"glow_opacity")
        self.glow_animation.setDuration(2000)
        self.glow_animation.setLoopCount(-1)
        self.glow_animation.setStartValue(0.3)
        self.glow_animation.setKeyValueAt(0.5, 0.8)
        self.glow_animation.setEndValue(0.3)
        self.glow_animation.setEasingCurve(QEasingCurve.Type.InOutSine)
        self.glow_animation.start()

        # Breathing animation
        self.breathe_animation = QPropertyAnimation(self, b"scale_factor")
        self.breathe_animation.setDuration(4000)
        self.breathe_animation.setLoopCount(-1)
        self.breathe_animation.setStartValue(1.0)
        self.breathe_animation.setKeyValueAt(0.5, 1.08)
        self.breathe_animation.setEndValue(1.0)
        self.breathe_animation.setEasingCurve(QEasingCurve.Type.InOutCubic)
        self.breathe_animation.start()

        # Rotation animation
        self.rotation_animation = QPropertyAnimation(self, b"rotation_angle")
        self.rotation_animation.setDuration(20000)
        self.rotation_animation.setLoopCount(-1)
        self.rotation_animation.setStartValue(0.0)
        self.rotation_animation.setEndValue(360.0)
        self.rotation_animation.setEasingCurve(QEasingCurve.Type.Linear)
        self.rotation_animation.start()

        # Pulse animation
        self.pulse_animation = QPropertyAnimation(self, b"pulse_intensity")
        self.pulse_animation.setDuration(1500)
        self.pulse_animation.setLoopCount(-1)
        self.pulse_animation.setStartValue(1.0)
        self.pulse_animation.setKeyValueAt(0.5, 1.15)
        self.pulse_animation.setEndValue(1.0)
        self.pulse_animation.setEasingCurve(QEasingCurve.Type.InOutQuad)
        self.pulse_animation.start()

    def get_check_progress(self):
        return self._check_progress

    def set_check_progress(self, value):
        self._check_progress = value
        self.update()

    def get_glow_opacity(self):
        return self._glow_opacity

    def set_glow_opacity(self, value):
        self._glow_opacity = value
        self.update()

    def get_scale_factor(self):
        return self._scale_factor

    def set_scale_factor(self, value):
        self._scale_factor = value
        self.update()

    def get_rotation_angle(self):
        return self._rotation_angle

    def set_rotation_angle(self, value):
        self._rotation_angle = value
        self.update()

    def get_pulse_intensity(self):
        return self._pulse_intensity

    def set_pulse_intensity(self, value):
        self._pulse_intensity = value
        self.update()

    check_progress = Property(float, get_check_progress, set_check_progress)
    glow_opacity = Property(float, get_glow_opacity, set_glow_opacity)
    scale_factor = Property(float, get_scale_factor, set_scale_factor)
    rotation_angle = Property(float, get_rotation_angle, set_rotation_angle)
    pulse_intensity = Property(float, get_pulse_intensity, set_pulse_intensity)

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
        painter.scale(side / 240.0, side / 240.0)

        # Draw outer rings with rotation
        painter.save()
        painter.rotate(self._rotation_angle)
        for i in range(3):
            radius = 120 + (i * 15)
            ring_color = QColor(136, 192, 208, int(30 - i * 10))
            painter.setPen(QPen(ring_color, 2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(-radius, -radius, radius * 2, radius * 2)
        painter.restore()

        # Draw multi-layered glow
        for layer in range(4):
            glow_color = QColor(0, 255, 127) if self.is_protected else QColor(255, 80, 80)
            gradient = QRadialGradient(0, 0, 130 - layer * 20)
            opacity = self._glow_opacity * (0.4 - layer * 0.08) * self._pulse_intensity
            glow_color.setAlphaF(opacity)
            gradient.setColorAt(0.6, glow_color)
            glow_color.setAlphaF(0)
            gradient.setColorAt(1.0, glow_color)
            painter.setBrush(QBrush(gradient))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(-130 + layer * 10, -130 + layer * 10,
                              (130 - layer * 10) * 2, (130 - layer * 10) * 2)

        # Draw shield with enhanced gradient
        path = QPainterPath()
        path.moveTo(0, -95)
        path.cubicTo(85, -85, 85, 0, 85, 0)
        path.lineTo(85, 45)
        path.quadTo(85, 100, 0, 110)
        path.quadTo(-85, 100, -85, 45)
        path.lineTo(-85, 0)
        path.cubicTo(-85, -85, 0, -95, 0, -95)

        shield_gradient = QLinearGradient(0, -95, 0, 110)
        shield_gradient.setColorAt(0, QColor("#4C566A"))
        shield_gradient.setColorAt(0.3, QColor("#434C5E"))
        shield_gradient.setColorAt(0.7, QColor("#3B4252"))
        shield_gradient.setColorAt(1, QColor("#2E3440"))
        painter.fillPath(path, QBrush(shield_gradient))

        # Draw shield border with glow
        border_color = QColor("#88C0D0")
        border_color.setAlphaF(0.8 * self._pulse_intensity)
        painter.setPen(QPen(border_color, 3))
        painter.drawPath(path)

        progress = self._check_progress

        # Draw energy lines inside shield
        if self.is_protected:
            painter.save()
            painter.setPen(QPen(QColor(136, 192, 208, int(100 * progress)), 2))
            for i in range(-60, 61, 20):
                painter.drawLine(i, -80, i, 90)
            painter.restore()

        # Draw icon or cross
        if self.is_protected:
            if self.hydra_pixmap and not self.hydra_pixmap.isNull():
                painter.setOpacity(progress)
                pixmap_rect = QRect(-80, -90, 160, 160)
                painter.drawPixmap(pixmap_rect, self.hydra_pixmap)
                painter.setOpacity(1.0)
        else:
            painter.setPen(QPen(QColor("white"), 16, Qt.PenStyle.SolidLine,
                              Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            painter.drawLine(int(-40 * progress), int(-40 * progress),
                           int(40 * progress), int(40 * progress))
            painter.drawLine(int(40 * progress), int(-40 * progress),
                           int(-40 * progress), int(40 * progress))


# --- Animated Status Card Widget ---
class StatusCard(QFrame):
    """Modern card widget with hover effects and animations."""
    def __init__(self, title, value, icon_text="", parent=None):
        super().__init__(parent)
        self.setObjectName("status_card")
        self.setMinimumHeight(120)
        self._hover_scale = 1.0
        self.scale_animation = None
        self.original_width = 0
        self.original_height = 0

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        if icon_text:
            icon_label = QLabel(icon_text)
            icon_label.setStyleSheet("font-size: 32px; color: #88C0D0;")
            layout.addWidget(icon_label)

        title_label = QLabel(title)
        title_label.setObjectName("card_title")
        layout.addWidget(title_label)

        self.value_label = QLabel(value)
        self.value_label.setObjectName("card_value")
        layout.addWidget(self.value_label)

        self.hover_animation = QPropertyAnimation(self, b"hover_scale")
        self.hover_animation.setDuration(200)
        self.hover_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 5)
        self.setGraphicsEffect(shadow)

        # Store original size after widget is shown and laid out
        QTimer.singleShot(0, self._store_original_size)

    def _store_original_size(self):
        """Store original dimensions after widget is laid out"""
        self.original_width = self.width()
        self.original_height = self.height()

    def get_hover_scale(self):
        return self._hover_scale

    def set_hover_scale(self, value):
        """Animate widget scaling on hover"""
        if self._hover_scale == value:
            return

        self._hover_scale = value

        # Only animate if we have valid dimensions
        if self.original_width == 0 or self.original_height == 0:
            return

        # Get current geometry
        current = self.geometry()
        center = current.center()

        # Calculate new scaled size
        new_width = int(self.original_width * value)
        new_height = int(self.original_height * value)

        # Create rect centered on original position
        scaled_rect = QRect(0, 0, new_width, new_height)
        scaled_rect.moveCenter(center)

        # Create/reuse animation
        if self.scale_animation is None:
            self.scale_animation = QPropertyAnimation(self, b"geometry")
            self.scale_animation.setDuration(150)
            self.scale_animation.setEasingCurve(QEasingCurve.Type.OutCubic)

        self.scale_animation.stop()
        self.scale_animation.setEndValue(scaled_rect)
        self.scale_animation.start()

    hover_scale = Property(float, get_hover_scale, set_hover_scale)

    def enterEvent(self, event):
        self.hover_animation.setStartValue(1.0)
        self.hover_animation.setEndValue(1.05)
        self.hover_animation.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.hover_animation.setStartValue(1.05)
        self.hover_animation.setEndValue(1.0)
        self.hover_animation.start()
        super().leaveEvent(event)

# --- Worker Thread for Background Tasks ---
class Worker(QThread):
    """
    Handles long-running tasks in the background to prevent the UI from freezing.
    """
    output_signal = Signal(str)

    def __init__(self, task_type, *args):
        super().__init__()
        self.task_type = task_type
        self.args = args

    def update_definitions(self):
        try:
            self.output_signal.emit("[*] Checking virus definitions...")
            updated = False
            # Check if freshclam exists before trying to run it
            if not os.path.exists(freshclam_path):
                 self.output_signal.emit(f"[!] Error: freshclam not found at '{freshclam_path}'. Please check the path.")
                 return

            for file_path in clamav_file_paths:
                if os.path.exists(file_path):
                    file_mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    if (datetime.now() - file_mod_time) > timedelta(hours=12):
                        updated = True
                        break
                else: # If a definition file doesn't exist, we should update.
                    updated = True
                    break

            if updated:
                self.output_signal.emit("[*] Definitions are outdated or missing. Starting update...")
                # Using subprocess.run for simplicity. For real-time output, Popen is better.
                result = subprocess.run([freshclam_path], capture_output=True, text=True, encoding="utf-8", errors="ignore")
                if result.returncode == 0:
                    reload_clamav_database()
                    self.output_signal.emit("[+] Virus definitions updated successfully and ClamAV restarted.")
                    self.output_signal.emit(f"Output:\n{result.stdout}")
                else:
                    self.output_signal.emit(f"[!] Failed to update ClamAV definitions. Error:\n{result.stderr}")
            else:
                self.output_signal.emit("[*] Definitions are already up-to-date.")
        except Exception as e:
            self.output_signal.emit(f"[!] Error updating definitions: {str(e)}")

    def update_hayabusa_rules(self):
        """
        Updates Hayabusa rules to the latest version from the GitHub repository.
        """
        try:
            self.output_signal.emit("[*] Updating Hayabusa rules...")

            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            cmd = [hayabusa_path, "update-rules"]
            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

            # Wait for completion and optionally emit output
            stdout, stderr = process.communicate()
            if stdout:
                self.output_signal.emit(f"[Hayabusa] {stdout.strip()}")
            if stderr:
                self.output_signal.emit(f"[Hayabusa-ERR] {stderr.strip()}")

            if process.returncode == 0:
                self.output_signal.emit("[+] Hayabusa rules update completed successfully!")
            else:
                self.output_signal.emit(f"[!] Hayabusa rules update failed (code {process.returncode})")

        except Exception as e:
            self.output_signal.emit(f"[!] Error updating Hayabusa rules: {str(e)}")

        async def run_real_time_protection_async(self):
            """Run real-time protection asynchronously and keep coroutine alive"""
            try:
                async for output in run_real_time_protection_with_yield_async():
                    try:
                        self.output_signal.emit(str(output))
                    except Exception:
                        logger.exception("Failed to emit output from real-time protection.")
            except Exception:
                logger.exception("Unhandled exception in real-time protection")
                try:
                    self.output_signal.emit(f"[!] Error during real-time protection: {traceback.format_exc()}")
                except Exception:
                    logger.exception("Failed to emit exception message")

        async def run_hayabusa_live_timeline_async(self):
            """Run Hayabusa CSV timeline in live analysis mode asynchronously."""

            try:
                self.output_signal.emit("[*] Starting Hayabusa live timeline analysis...")

                if not os.path.exists(hayabusa_path):
                    self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                    return

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_dir = os.path.join(log_directory, f"hayabusa_live_{timestamp}")
                os.makedirs(output_dir, exist_ok=True)
                output_file = os.path.join(output_dir, f"hayabusa_live_{timestamp}.csv")

                cmd = [
                    hayabusa_path, "csv-timeline", "-l",
                    "-o", output_file, "--profile", "standard", "-m", "critical"
                ]
                self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

                # --- Run subprocess asynchronously ---
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    cwd=os.path.dirname(hayabusa_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    text=True
                )

                # --- Async stdout/stderr reader ---
                async def stream_reader(pipe, label):
                    async for line in pipe:
                        self.output_signal.emit(f"[{label}] {line.strip()}")

                asyncio.create_task(stream_reader(process.stdout, "Hayabusa"))
                asyncio.create_task(stream_reader(process.stderr, "Hayabusa-ERR"))

                # --- Async CSV tailer ---
                async def tail_csv_and_analyze(csv_file_path):
                    # Wait for file to exist
                    while not os.path.exists(csv_file_path):
                        await asyncio.sleep(0.01)

                    seen = set()
                    while True:
                        try:
                            async with aiofiles.open(csv_file_path, mode='r', encoding='utf-8', errors='ignore') as f:
                                reader = csv.DictReader(await f.readlines())
                                for row in reader:
                                    key = (row.get('Timestamp'), row.get('EventID'))
                                    if key not in seen:
                                        seen.add(key)
                                        level = row.get('Level', '').lower()
                                        if level in ('critical', 'crit'):
                                            notify_user_hayabusa_critical(
                                                event_log=f"{row.get('Channel')} (EID: {row.get('EventID')})",
                                                rule_title=row.get('RuleTitle'),
                                                details=row.get('Details'),
                                                computer=row.get('Computer'),
                                            )
                                            self.output_signal.emit(
                                                f"[!] LIVE CRITICAL [{row.get('Timestamp')}]: "
                                                f"{row.get('RuleTitle')} | {row.get('Computer')} "
                                                f"| {row.get('Channel')} | {row.get('Details')[:100]}"
                                            )
                            await asyncio.sleep(0.1)
                        except Exception as e:
                            self.output_signal.emit(f"[!] CSV parse error: {str(e)}")
                            await asyncio.sleep(0.5)

                # Use asyncio task for CSV tailer
                asyncio.create_task(tail_csv_and_analyze(output_file))

                self.output_signal.emit("[*] Hayabusa live monitoring started (running indefinitely).")

            except Exception as e:
                self.output_signal.emit(f"[!] Error running Hayabusa live timeline: {str(e)}")

    def run(self):
        """The entry point for the QThread worker.

        Dispatches tasks by:
        1) calling a method on this Worker matching the task_type (preferred), or
        2) falling back to a short explicit task mapping, or
        3) reporting the task as unknown.
        """
        try:
            # 1) If there's a method on this Worker that matches task_type, call it.
            method = getattr(self, self.task_type, None)
            if callable(method):
                try:
                    method(*self.args)
                except TypeError:
                    # In case args don't match signature, try without args
                    method()
                return

            # 2) Fallback mapping for task_type strings that are not methods
            task_mapping = {
                "update_defs": self.update_definitions,
            }

            func = task_mapping.get(self.task_type)
            if func:
                try:
                    func(*self.args)
                except TypeError:
                    func()
                return

            # 3) Unknown task
            self.output_signal.emit(f"[!] Unknown task type: {self.task_type}")
        except Exception as e:
            if not self.stop_requested:
                # Keep this human-readable and safe for the GUI
                err = f"[!] Worker thread error ({self.task_type}): {str(e)}"
                self.output_signal.emit(err)
                logger.exception("Worker.run exception for task %s", self.task_type)

# --- Main Application Window ---
class AntivirusApp(QWidget):
    def __init__(self):
        super().__init__()
        self.workers = []
        self.log_outputs = []
        self.animation_group = QParallelAnimationGroup()
        self.worker_lock = threading.RLock()

        self.apply_extreme_stylesheet()
        self.setup_ui()
        QTimer.singleShot(0, lambda: asyncio.create_task(self.run_startup_task_async()))

    async def run_startup_task_async(self):
        """Run automatic real-time protection and Hayabusa analysis on startup"""
        self.append_log_output("[*] Starting automatic real-time protection...")
        # Run real-time protection asynchronously
        worker_rt = Worker("run_real_time_protection_async")
        worker_rt.output_signal.connect(self.append_log_output)
        self.workers.append(worker_rt)
        worker_rt.start()

        # Run Hayabusa live analysis asynchronously
        worker_haya = Worker("run_hayabusa_live_timeline_async")
        worker_haya.output_signal.connect(self.append_log_output)
        self.workers.append(worker_haya)
        worker_haya.start()

    def apply_extreme_stylesheet(self):
        stylesheet = """
            QWidget {
                background-color: #2E3440;
                color: #D8DEE9;
                font-family: 'Segoe UI', 'SF Pro Display', Arial, sans-serif;
                font-size: 14px;
            }

            QTextEdit {
                background-color: #3B4252;
                border: 2px solid #4C566A;
                border-radius: 10px;
                padding: 12px;
                color: #ECEFF4;
                font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
                font-size: 13px;
            }

            QTextEdit:focus {
                border: 2px solid #88C0D0;
            }

            QLineEdit {
                background-color: #3B4252;
                border: 2px solid #4C566A;
                border-radius: 8px;
                padding: 10px 15px;
                color: #ECEFF4;
                font-size: 14px;
            }

            QLineEdit:focus {
                border: 2px solid #88C0D0;
                background-color: #434C5E;
            }

            #sidebar {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #2E3440, stop:1 #232831);
                max-width: 240px;
                border-right: 1px solid #4C566A;
            }

            #logo {
                color: #88C0D0;
                font-size: 32px;
                font-weight: bold;
                letter-spacing: 2px;
            }

            #nav_button {
                background-color: transparent;
                border: none;
                color: #D8DEE9;
                padding: 14px 16px;
                text-align: left;
                border-radius: 8px;
                font-size: 13px;
                font-weight: 500;
                margin: 2px 8px;
            }

            #nav_button:hover {
                background-color: #434C5E;
                color: #ECEFF4;
            }

            #nav_button:checked {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #88C0D0, stop:1 #81A1C1);
                color: #2E3440;
                font-weight: bold;
            }

            #page_title {
                font-size: 32px;
                font-weight: 300;
                color: #ECEFF4;
                padding-bottom: 20px;
                letter-spacing: 1px;
            }

            #page_subtitle {
                font-size: 18px;
                color: #A3BE8C;
                font-weight: 500;
            }

            #version_label {
                font-size: 13px;
                color: #81A1C1;
                font-weight: 400;
            }

            #action_button {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #5E81AC, stop:1 #5273A0);
                color: #ECEFF4;
                border-radius: 10px;
                padding: 14px 24px;
                font-size: 14px;
                font-weight: bold;
                border: none;
                min-width: 180px;
            }

            #action_button:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #81A1C1, stop:1 #6B8DB8);
            }

            #action_button:pressed {
                background: #4C6A94;
            }

            #warning_text {
                font-size: 13px;
                line-height: 1.6;
            }

            #status_card {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #3B4252, stop:1 #343D4C);
                border: 2px solid #4C566A;
                border-radius: 12px;
                padding: 15px;
            }

            #status_card:hover {
                border: 2px solid #88C0D0;
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #434C5E, stop:1 #3B4554);
            }

            #card_title {
                font-size: 13px;
                color: #81A1C1;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 1px;
            }

            #card_value {
                font-size: 24px;
                color: #ECEFF4;
                font-weight: bold;
            }

            QProgressBar {
                border: 2px solid #4C566A;
                border-radius: 8px;
                text-align: center;
                background-color: #3B4252;
                color: #ECEFF4;
                font-weight: bold;
            }

            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #88C0D0, stop:0.5 #81A1C1, stop:1 #5E81AC);
                border-radius: 6px;
            }

            QScrollBar:vertical {
                border: none;
                background-color: #3B4252;
                width: 12px;
                border-radius: 6px;
            }

            QScrollBar::handle:vertical {
                background-color: #5E81AC;
                border-radius: 6px;
                min-height: 30px;
            }

            QScrollBar::handle:vertical:hover {
                background-color: #81A1C1;
            }

            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """
        self.setStyleSheet(stylesheet)

    def append_log_output(self, text):
        current_page_index = self.main_stack.currentIndex()
        if 0 <= current_page_index < len(self.log_outputs):
            log_widget = self.log_outputs[current_page_index]
            if log_widget:
                log_widget.append(text)
                log_widget.verticalScrollBar().setValue(
                    log_widget.verticalScrollBar().maximum()
                )

    def on_worker_finished(self, worker):
        self.append_log_output(f"[+] Task '{worker.task_type}' finished.")
        with self.worker_lock:
            if worker in self.workers:
                self.workers.remove(worker)
        with self.worker_lock:
            if not self.workers:
                if hasattr(self, 'shield_widget'):
                    self.shield_widget.set_status(True)
                if hasattr(self, 'status_text'):
                    self.status_text.setText("Ready for real time protection!")

    def _update_ui_for_worker_start(self, task_type):
        self.append_log_output(f"[*] Task '{task_type}' started.")
        if hasattr(self, 'shield_widget'):
            self.shield_widget.set_status(False)
        if hasattr(self, 'status_text'):
            self.status_text.setText("System is busy...")

    def start_worker(self, task_type, *args):
        try:
            worker = Worker(task_type, *args)
            worker.output_signal.connect(self.append_log_output)
            worker.finished.connect(lambda: self.on_worker_finished(worker))
            with self.worker_lock:
                self.workers.append(worker)
            worker.start()
            self._update_ui_for_worker_start(task_type)
        except Exception as e:
            self.append_log_output(f"[!] Error starting task '{task_type}': {str(e)}")

    def switch_page_with_animation(self, index):
        if (self.animation_group.state() == QParallelAnimationGroup.State.Running or
            self.main_stack.currentIndex() == index):
            return
        current_widget = self.main_stack.currentWidget()
        next_widget = self.main_stack.widget(index)
        current_index = self.main_stack.currentIndex()
        slide_out_x = -self.main_stack.width() if index > current_index else self.main_stack.width()
        slide_in_x = -slide_out_x
        next_widget.move(slide_in_x, 0)
        next_widget.show()
        next_widget.raise_()
        current_pos_anim = QPropertyAnimation(current_widget, b"pos")
        current_pos_anim.setEndValue(QPoint(slide_out_x, 0))
        next_pos_anim = QPropertyAnimation(next_widget, b"pos")
        next_pos_anim.setEndValue(QPoint(0, 0))
        self.animation_group = QParallelAnimationGroup()
        for anim in [current_pos_anim, next_pos_anim]:
            anim.setDuration(500)
            anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
            self.animation_group.addAnimation(anim)
        self.animation_group.finished.connect(lambda: self.main_stack.setCurrentIndex(index))
        self.animation_group.start()

    def closeEvent(self, event):
        # Don't close, just hide the window
        event.ignore()
        self.hide()
        self.append_log_output("[*] Application minimized to system tray (window hidden)")

    def create_status_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(30)

        # Status cards row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(20)

        # Add the card layout to the main layout
        layout.addLayout(cards_layout)

        # Main status area
        main_area = QHBoxLayout()
        main_area.setSpacing(40)

        self.shield_widget = ShieldWidget()
        main_area.addWidget(self.shield_widget, 2)

        status_vbox = QVBoxLayout()
        status_vbox.addStretch()

        title = QLabel("System Status")
        title.setObjectName("page_title")
        self.status_text = QLabel("Ready for real time protection!")
        self.status_text.setObjectName("page_subtitle")

        version_label = QLabel(WINDOW_TITLE)
        version_label.setObjectName("version_label")
        defs_label = QLabel(get_latest_clamav_def_time())
        defs_label.setObjectName("version_label")

        status_vbox.addWidget(title)
        status_vbox.addWidget(self.status_text)
        status_vbox.addSpacing(30)
        status_vbox.addWidget(version_label)
        status_vbox.addWidget(defs_label)
        status_vbox.addStretch()

        main_area.addLayout(status_vbox, 3)
        layout.addLayout(main_area)

        self.log_outputs.append(None)
        return page

    def create_task_page(self, title_text, task_name, additional_tasks=None):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        header_layout = QHBoxLayout()
        title = QLabel(title_text)
        title.setObjectName("page_title")
        header_layout.addWidget(title)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        button_container = QHBoxLayout()
        button_container.setSpacing(15)

        # Main button
        button = QPushButton(f"Run {title_text}")
        button.setObjectName("action_button")
        button.clicked.connect(lambda: self.start_worker(task_name))
        button_container.addWidget(button)

        # Additional buttons if provided
        if additional_tasks:
            for btn_text, task in additional_tasks:
                extra_btn = QPushButton(btn_text)
                extra_btn.setObjectName("action_button")
                extra_btn.clicked.connect(lambda checked, t=task: self.start_worker(t))
                button_container.addWidget(extra_btn)

        button_container.addStretch()
        layout.addLayout(button_container)

        progress_bar = QProgressBar()
        progress_bar.setVisible(False)
        progress_bar.setMaximumHeight(8)
        layout.addWidget(progress_bar)

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

        about_text = QLabel(
            "HydraDragon Antivirus is FOSS Antivirus with Real Time Protection. "
        )
        about_text.setWordWrap(True)
        layout.addWidget(about_text)

        buttons_layout = QVBoxLayout()
        buttons_layout.setSpacing(15)

        github_button = QPushButton("View Project on GitHub")
        github_button.setObjectName("action_button")
        github_button.clicked.connect(lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus"))
        buttons_layout.addWidget(github_button, 0, Qt.AlignmentFlag.AlignLeft)

        layout.addLayout(buttons_layout)
        return page

    def create_main_content(self):
        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self.create_status_page())
        # Updated line below:
        self.main_stack.addWidget(self.create_task_page(
            "Update Definitions",
            "update_defs"
        ))
        self.main_stack.addWidget(self.create_about_page())
        return self.main_stack

    def create_sidebar(self):
        sidebar_frame = QFrame()
        sidebar_frame.setObjectName("sidebar")
        sidebar_layout = QVBoxLayout(sidebar_frame)
        sidebar_layout.setContentsMargins(15, 25, 15, 25)
        sidebar_layout.setSpacing(8)

        logo_area = QHBoxLayout()
        logo_area.setSpacing(12)

        icon_widget = HydraIconWidget()
        icon_widget.setFixedSize(36, 36)

        logo_label = QLabel("HYDRA")
        logo_label.setObjectName("logo")

        logo_area.addWidget(icon_widget)
        logo_area.addWidget(logo_label)
        logo_area.addStretch()

        sidebar_layout.addLayout(logo_area)
        sidebar_layout.addSpacing(30)

        nav_buttons = [
            ("🏠", "Status"),
            ("🔄", "Update Definitions"),
            ("i", "About")
        ]

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        for i, (icon, name) in enumerate(nav_buttons):
            button_layout = QHBoxLayout()
            button_layout.setSpacing(10)

            button = QPushButton(f"{icon}  {name}")
            button.setCheckable(True)
            button.setObjectName("nav_button")
            button.clicked.connect(lambda checked, index=i: self.switch_page_with_animation(index))

            sidebar_layout.addWidget(button)
            self.nav_group.addButton(button, i)

        self.nav_group.button(0).setChecked(True)
        sidebar_layout.addStretch()

        return sidebar_frame

    def setup_ui(self):
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            logger.error(f"Icon file not found at: {icon_path}")

        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(1100, 800)
        self.resize(1400, 900)

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self.create_sidebar())
        main_layout.addWidget(self.create_main_content(), 1)

def main():
    app = QApplication(sys.argv)

    # Wrap the Qt event loop with qasync
    loop = QEventLoop(app)
    asyncio.set_event_loop(loop)

    window = AntivirusApp()
    window.show()

    # Start the combined asyncio + Qt event loop
    with loop:
        loop.run_forever()

if __name__ == "__main__":
    main()
