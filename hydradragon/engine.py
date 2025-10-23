#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import traceback
import webbrowser
import subprocess
import csv
import aiofiles
from qasync import QEventLoop, asyncSlot

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
from PySide6.QtCore import (Qt, QPropertyAnimation, QEasingCurve,
                            Signal, QPoint, QParallelAnimationGroup, Property, QRect, QTimer)
from PySide6.QtGui import (QColor, QPainter, QBrush, QLinearGradient, QPen,
                           QPainterPath, QRadialGradient, QIcon, QPixmap)

# --- Import necessary functions from antivirus script ---
from hydradragon.antivirus_scripts.antivirus import (
    run_real_time_protection_with_yield_async, # This MUST be an async generator
    reload_clamav_database,
    get_latest_clamav_def_time
)
# --- Import paths ---
try:
    from hydradragon.antivirus_scripts.path_and_variables import (
        freshclam_path,
        icon_path,
        hayabusa_path,
        WINDOW_TITLE,
        clamav_file_paths,
    )
except ImportError as e:
    logger.critical(f"Failed to import paths: {e}")
    # Define dummy paths
    freshclam_path = "freshclam"
    icon_path = "icon.png"
    hayabusa_path = "hayabusa"
    WINDOW_TITLE = "HydraDragon (Import Failed)"
    clamav_file_paths = []

# --- Import notifier ---
try:
    from hydradragon.antivirus_scripts.notify_user import notify_user_hayabusa_critical
except ImportError as e:
    logger.critical(f"Failed to import notifier: {e}")
    def notify_user_hayabusa_critical(*args, **kwargs): logger.error("Notifier import failed!")


# --- Custom Hydra Icon Widget ---
class HydraIconWidget(QWidget):
    """A custom widget to draw the Hydra Dragon icon."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.pixmap = None
        if os.path.exists(icon_path):
            try:
                self.pixmap = QPixmap(icon_path)
                if self.pixmap.isNull():
                     logger.error(f"Failed to load icon pixmap from {icon_path}. It might be corrupted or an unsupported format.")
                     self.pixmap = None # Ensure it's None if loading failed
            except Exception as e:
                 logger.error(f"Error loading icon pixmap from {icon_path}: {e}")
                 self.pixmap = None
        else:
            logger.error(f"Sidebar icon not found at {icon_path}. Drawing fallback.")
        self.setMinimumSize(36, 36) # Ensure it has a size

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        # Guard against invalid dimensions
        if self.width() <= 0 or self.height() <= 0:
            return
        
        if self.pixmap and not self.pixmap.isNull():
            scaled_pixmap = self.pixmap.scaled(
                self.size(), 
                Qt.AspectRatioMode.KeepAspectRatio, 
                Qt.TransformationMode.SmoothTransformation
            )
            x = int((self.width() - scaled_pixmap.width()) / 2)
            y = int((self.height() - scaled_pixmap.height()) / 2)
            painter.drawPixmap(x, y, scaled_pixmap)
        else:
            # Fallback drawing
            painter.save()
            try:
                painter.translate(self.width() / 2 - 15, self.height() / 2 - 10)
                
                primary_color = QColor("#88C0D0")
                shadow_color = QColor("#4C566A")
                path = QPainterPath()
                
                # Main body
                path.moveTo(0, 20)
                path.quadTo(15, 0, 30, 20)
                path.quadTo(15, 10, 0, 20)
                
                # Left head
                path.moveTo(5, 15)
                path.cubicTo(-20, 0, -10, -25, 0, -20)
                path.quadTo(-5, -18, 5, 15)
                
                # Right head
                path.moveTo(25, 15)
                path.cubicTo(50, 0, 40, -25, 30, -20)
                path.quadTo(35, -18, 25, 15)
                
                # Center head
                path.moveTo(15, 10)
                path.cubicTo(10, -20, 20, -20, 15, 10)
                
                painter.setPen(QPen(primary_color, 3))
                painter.setBrush(shadow_color)
                painter.drawPath(path)
            finally:
                painter.restore()

# --- Advanced Shield Widget with Particle Effects ---
class ShieldWidget(QWidget):
    """Shield widget with defensive paint logic to avoid crashes."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAutoFillBackground(True)
        self.setMinimumSize(280, 280)

        # State
        self.is_protected = True
        self._glow_opacity = 0.0
        self._check_progress = 1.0
        self._scale_factor = 1.0
        self._rotation_angle = 0.0
        self._pulse_intensity = 1.0

        # Cached resources
        self.hydra_pixmap = None
        self._cached_scaled_pixmap = None
        self._shield_path_cache = None  # tuple: (side, QPainterPath)

        # Try to load icon if path exists in module (icon_path)
        try:
            from hydradragon.antivirus_scripts.path_and_variables import icon_path  # type: ignore
        except Exception:
            icon_path = None

        if icon_path and isinstance(icon_path, str):
            try:
                p = QPixmap(icon_path)
                if not p.isNull():
                    self.hydra_pixmap = p
                else:
                    logger.debug(f"ShieldWidget: pixmap at {icon_path} is null.")
            except Exception as e:
                logger.exception(f"ShieldWidget: error loading pixmap {icon_path}: {e}")

        # Animations kept in calling code — properties will be updated by external QPropertyAnimations
        # (We don't start/define animations here to keep this class focused on defensive painting.)

    # -------------------------
    # Property definitions (debounced update)
    # -------------------------
    def _debounced_update(self):
        # Schedule a single update on the event loop (coalesces multiple calls)
        QTimer.singleShot(0, self.update)

    def get_check_progress(self): return self._check_progress
    def set_check_progress(self, value):
        v = float(value)
        if abs(self._check_progress - v) < 1e-6:
            return
        self._check_progress = v
        self._debounced_update()
    check_progress = Property(float, get_check_progress, set_check_progress)

    def get_glow_opacity(self): return self._glow_opacity
    def set_glow_opacity(self, value):
        v = float(value)
        if abs(self._glow_opacity - v) < 1e-6:
            return
        self._glow_opacity = v
        self._debounced_update()
    glow_opacity = Property(float, get_glow_opacity, set_glow_opacity)

    def get_scale_factor(self): return self._scale_factor
    def set_scale_factor(self, value):
        v = float(value)
        if abs(self._scale_factor - v) < 1e-6:
            return
        self._scale_factor = v
        self._debounced_update()
    scale_factor = Property(float, get_scale_factor, set_scale_factor)

    def get_rotation_angle(self): return self._rotation_angle
    def set_rotation_angle(self, value):
        v = float(value)
        if abs(self._rotation_angle - v) < 1e-6:
            return
        self._rotation_angle = v
        self._debounced_update()
    rotation_angle = Property(float, get_rotation_angle, set_rotation_angle)

    def get_pulse_intensity(self): return self._pulse_intensity
    def set_pulse_intensity(self, value):
        v = float(value)
        if abs(self._pulse_intensity - v) < 1e-6:
            return
        self._pulse_intensity = v
        self._debounced_update()
    pulse_intensity = Property(float, get_pulse_intensity, set_pulse_intensity)

    # -------------------------
    # Helpers
    # -------------------------
    def set_status(self, is_protected: bool):
        """Called to set protected/busy visuals from main thread only."""
        if self.is_protected != bool(is_protected):
            self.is_protected = bool(is_protected)
            # animate check_progress externally, but ensure we repaint
            self._debounced_update()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Rebuild cached pixmap to fit current size
        try:
            if self.hydra_pixmap and not self.hydra_pixmap.isNull():
                # Keep the icon area reasonable (use a fraction of widget)
                target_size = int(min(self.width(), self.height()) * 0.45)
                if target_size <= 0:
                    self._cached_scaled_pixmap = None
                else:
                    self._cached_scaled_pixmap = self.hydra_pixmap.scaled(
                        target_size, target_size,
                        transformMode=Qt.TransformationMode.SmoothTransformation
                    )
            else:
                self._cached_scaled_pixmap = None
        except Exception:
            logger.exception("ShieldWidget.resizeEvent: error scaling pixmap")

        # Invalidate shield path cache so it can be rebuilt for new size
        self._shield_path_cache = None

    def _ensure_shield_path(self, side: int):
        """Lazily build a QPainterPath for the shield at the given 'side' scale."""
        try:
            cache = self._shield_path_cache
            if cache and cache[0] == side:
                return cache[1]
            # Build a normalized path for a base coordinate system (centered at 0)
            path = QPainterPath()
            path.moveTo(0, -95)
            path.cubicTo(85, -85, 85, 0, 85, 0)
            path.lineTo(85, 45)
            path.quadTo(85, 100, 0, 110)
            path.quadTo(-85, 100, -85, 45)
            path.lineTo(-85, 0)
            path.cubicTo(-85, -85, 0, -95, 0, -95)
            # Cache with the side so we can scale in paint (we still scale via painter transforms)
            self._shield_path_cache = (side, path)
            return path
        except Exception:
            logger.exception("ShieldWidget._ensure_shield_path: failed to build path")
            return QPainterPath()

    # -------------------------
    # Main paint
    # -------------------------
    def paintEvent(self, event):
        try:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)

            w, h = self.width(), self.height()
            if w <= 0 or h <= 0:
                return
            side = min(w, h)
            if side <= 0:
                return

            # Center & scaling
            center_x, center_y = w / 2.0, h / 2.0
            painter.save()
            try:
                # Apply transforms for rotation and breathing scale
                painter.translate(center_x, center_y)
                painter.scale(self._scale_factor, self._scale_factor)
                try:
                    ang = float(self._rotation_angle) % 360.0
                except Exception:
                    ang = 0.0
                painter.rotate(ang)
                base_scale = float(side) / 240.0
                # scale to normalized coordinates used in path construction
                painter.scale(base_scale, base_scale)

                # --- Outer rings (rotated) ---
                painter.save()
                try:
                    for i in range(3):
                        try:
                            radius = int(120 + (i * 15))
                            alpha = int(max(0, min(255, 30 - i * 10)))
                            ring_color = QColor(136, 192, 208)
                            ring_color.setAlpha(alpha)
                            pen = QPen(ring_color, 2)
                            painter.setPen(pen)
                            painter.setBrush(Qt.BrushStyle.NoBrush)
                            # drawEllipse with QPoint + radii
                            painter.drawEllipse(QPoint(0, 0), radius, radius)
                        except Exception:
                            logger.exception(f"ShieldWidget: error drawing ring i={i}")
                            continue
                finally:
                    painter.restore()

                # --- Elements not affected by rotation ---
                painter.save()
                try:
                    painter.resetTransform()
                    painter.translate(center_x, center_y)
                    painter.scale(self._scale_factor, self._scale_factor)
                    painter.scale(base_scale, base_scale)

                    # Multi-layer glow
                    for layer in range(4):
                        try:
                            base_opacity = (self._glow_opacity *
                                            (0.4 - layer * 0.08) *
                                            self._pulse_intensity)
                            opacity = max(0.0, min(1.0, float(base_opacity)))
                            glow_color = QColor(0, 255, 127) if self.is_protected else QColor(255, 80, 80)
                            # Use setAlphaF after clamping
                            glow_color.setAlphaF(opacity)

                            gradient_radius = max(1, int(130 - layer * 20))
                            gradient = QRadialGradient(0, 0, gradient_radius)
                            gradient.setColorAt(0.6, glow_color)
                            tmp = QColor(glow_color)
                            tmp.setAlphaF(0.0)
                            gradient.setColorAt(1.0, tmp)

                            painter.setBrush(QBrush(gradient))
                            painter.setPen(Qt.PenStyle.NoPen)

                            w_rect = max(2, gradient_radius * 2)
                            painter.drawEllipse(-gradient_radius, -gradient_radius, w_rect, w_rect)
                        except Exception:
                            logger.exception(f"ShieldWidget: error drawing glow layer={layer}")
                            continue

                    # Shield body
                    try:
                        shield_path = self._ensure_shield_path(side)
                        # Fill gradient
                        shield_gradient = QLinearGradient(0, -95, 0, 110)
                        shield_gradient.setColorAt(0, QColor("#4C566A"))
                        shield_gradient.setColorAt(0.3, QColor("#434C5E"))
                        shield_gradient.setColorAt(0.7, QColor("#3B4252"))
                        shield_gradient.setColorAt(1.0, QColor("#2E3440"))
                        painter.fillPath(shield_path, QBrush(shield_gradient))

                        border_color = QColor("#88C0D0")
                        border_alpha = max(0.0, min(1.0, 0.8 * self._pulse_intensity))
                        border_color.setAlphaF(border_alpha)
                        painter.setPen(QPen(border_color, 3))
                        painter.drawPath(shield_path)
                    except Exception:
                        logger.exception("ShieldWidget: error drawing shield path")

                    # Energy lines inside shield
                    if self.is_protected:
                        try:
                            progress_clamped = max(0.0, min(1.0, float(self._check_progress)))
                            alpha_value = int(max(0, min(255, 255 * progress_clamped)))
                            pen_color = QColor(136, 192, 208)
                            pen_color.setAlpha(alpha_value)
                            painter.setPen(QPen(pen_color, 2))

                            for x in range(-60, 61, 20):
                                try:
                                    painter.drawLine(int(x), -80, int(x), 90)
                                except Exception:
                                    logger.exception(f"ShieldWidget: error drawing energy line x={x}")
                                    continue
                        except Exception:
                            logger.exception("ShieldWidget: error in energy lines block")

                    # Draw icon or cross depending on protection state
                    try:
                        prog = max(0.0, min(1.0, float(self._check_progress)))
                        if self.is_protected:
                            pix = self._cached_scaled_pixmap
                            if pix and not pix.isNull():
                                painter.save()
                                try:
                                    painter.setOpacity(prog)
                                    # center the pixmap area
                                    pix_w, pix_h = pix.width(), pix.height()
                                    pix_x = int(-pix_w / 2)
                                    pix_y = int(-pix_h / 2)
                                    painter.drawPixmap(pix_x, pix_y, pix)
                                finally:
                                    painter.restore()
                        else:
                            painter.save()
                            try:
                                # Draw cross with wide pen
                                pen = QPen(QColor("white"), max(1, int(16 * prog)),
                                           Qt.PenStyle.SolidLine,
                                           Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
                                painter.setPen(pen)
                                v = int(40 * prog)
                                painter.drawLine(-v, -v, v, v)
                                painter.drawLine(v, -v, -v, v)
                            finally:
                                painter.restore()
                    except Exception:
                        logger.exception("ShieldWidget: error drawing center icon/cross")

                finally:
                    painter.restore()

            finally:
                painter.restore()

        except Exception:
            # Top-level paint exception: log and return to avoid crashing the UI thread.
            logger.exception("Exception in ShieldWidget.paintEvent")
            return

# --- Main Application Window ---
class AntivirusApp(QWidget):
    # Signal to append log messages safely from any thread/task
    log_signal = Signal(str)

    def __init__(self):
        super().__init__()
        self.active_tasks = set() # Keep track of running asyncio tasks
        self.log_outputs = [] # List to hold QTextEdit widgets for each page
        self.animation_group = QParallelAnimationGroup()
        self.defs_label = None # To update definition time

        self.apply_extreme_stylesheet()
        self.setup_ui()

        # Connect the signal to the slot
        self.log_signal.connect(self._append_log_output_slot)

        # Run startup tasks after UI is shown
        QTimer.singleShot(0, self.run_startup_tasks)

    def _append_log_output_slot(self, text):
        """Safely append text to the log widget of the current page."""
        try:
            current_page_index = self.main_stack.currentIndex()
            if 0 <= current_page_index < len(self.log_outputs):
                log_widget = self.log_outputs[current_page_index]
                if log_widget and isinstance(log_widget, QTextEdit):
                    log_widget.append(text)
                    # Scroll to bottom only if the scrollbar is already near the bottom
                    scrollbar = log_widget.verticalScrollBar()
                    at_bottom = scrollbar.value() >= (scrollbar.maximum() - 20) # Threshold
                    if at_bottom:
                         scrollbar.setValue(scrollbar.maximum())

        except Exception as e:
            logger.error(f"Error appending log to UI: {e}")

    def append_log_output(self, text):
        """Emit signal to append log message from any thread/task."""
        self.log_signal.emit(text)

    def apply_extreme_stylesheet(self):
        # Stylesheet remains the same as provided previously
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
                color: #A3BE8C; /* Greenish for 'Ready' */
                font-weight: 500;
            }
             #page_subtitle_busy { /* Add a style for busy */
                font-size: 18px;
                color: #EBCB8B; /* Yellowish for 'Busy' */
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
             #action_button:disabled { /* Style for disabled button */
                background: #4C566A;
                color: #8F9AA8;
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
                height: 10px; /* Make progress bar slimmer */
            }

            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #88C0D0, stop:0.5 #81A1C1, stop:1 #5E81AC);
                border-radius: 6px;
                 margin: 1px; /* Add margin for inset look */
            }

            QScrollBar:vertical {
                border: none;
                background-color: #3B4252;
                width: 12px;
                margin: 0px 0 0px 0; /* No margin */
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
                background: none;
            }
             QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
                background: none;
            }

        """
        self.setStyleSheet(stylesheet)

    # --- Task Execution ---

    def _update_ui_for_task_start(self, task_name):
        """Update UI to indicate a task is running."""
        self.append_log_output(f"[*] Task '{task_name}' started.")
        if hasattr(self, 'shield_widget'):
            self.shield_widget.set_status(False) # Show shield as busy/vulnerable
        if hasattr(self, 'status_text'):
            self.status_text.setText("System busy...")
            self.status_text.setObjectName("page_subtitle_busy") # Use busy style
            self.status_text.setStyle(self.style()) # Force style refresh
        # Disable buttons associated with this task if needed
        if hasattr(self, 'task_buttons') and task_name in self.task_buttons:
             self.task_buttons[task_name].setEnabled(False)

    def _update_ui_for_task_end(self, task_name):
        """Update UI when a task finishes."""
        self.append_log_output(f"[+] Task '{task_name}' finished.")
        # Only set shield to protected if *all* tasks are done
        if not self.active_tasks and hasattr(self, 'shield_widget'):
            self.shield_widget.set_status(True)
        if not self.active_tasks and hasattr(self, 'status_text'):
            self.status_text.setText("System protected!")
            self.status_text.setObjectName("page_subtitle") # Use ready style
            self.status_text.setStyle(self.style()) # Force style refresh
         # Re-enable button
        if hasattr(self, 'task_buttons') and task_name in self.task_buttons:
             self.task_buttons[task_name].setEnabled(True)
        # Update defs time if applicable
        if task_name == 'update_definitions' and self.defs_label:
            self.defs_label.setText(get_latest_clamav_def_time())

    async def run_task(self, task_name, coro_or_func, *args, is_async=True):
        """Runs an async coroutine or a blocking function via asyncio.to_thread."""
        if task_name in self.active_tasks:
            self.append_log_output(f"[*] Task '{task_name}' is already running.")
            return

        self.active_tasks.add(task_name)
        self._update_ui_for_task_start(task_name)
        try:
            if is_async:
                # Directly await the coroutine
                await coro_or_func(*args)
            else:
                # Run blocking function in a thread
                await asyncio.to_thread(coro_or_func, *args)
        except asyncio.CancelledError:
             self.append_log_output(f"[!] Task '{task_name}' was cancelled.")
             logger.info(f"Task {task_name} cancelled.")
        except Exception as e:
            error_msg = f"[!] Error in task '{task_name}': {traceback.format_exc()}"
            self.append_log_output(error_msg)
            logger.exception(f"Exception in task {task_name}")
        finally:
            if task_name in self.active_tasks:
                self.active_tasks.remove(task_name)
            self._update_ui_for_task_end(task_name)


    # --- Specific Task Implementations ---

    async def _run_real_time_protection_task(self):
        """Async task for real-time protection monitoring."""
        self.append_log_output("[*] Real-time protection monitoring starting...")
        try:
            async for output in run_real_time_protection_with_yield_async():
                self.append_log_output(str(output))
            self.append_log_output("[+] Real-time protection monitoring finished.")
        except Exception:
             error_msg = f"[!] Error during real-time protection: {traceback.format_exc()}"
             logger.exception("Unhandled exception in real-time protection")
             self.append_log_output(error_msg)


    async def _run_hayabusa_live_task(self):
        """Async task for Hayabusa live analysis."""
        self.append_log_output("[*] Starting Hayabusa live timeline analysis...")
        process = None # Keep track of the process
        csv_tail_task = None # Keep track of tailing task
        try:
            if not os.path.exists(hayabusa_path):
                self.append_log_output(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_live_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"hayabusa_live_{timestamp}.csv")

            cmd = [
                hayabusa_path, "csv-timeline", "-l",
                "-o", output_file, "--profile", "standard", "-m", "critical"
            ]
            self.append_log_output(f"[*] Running command: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=os.path.dirname(hayabusa_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def stream_reader(pipe, label):
                 if pipe is None: return
                 while True:
                     line_bytes = await pipe.readline()
                     if not line_bytes: break
                     line = line_bytes.decode('utf-8', errors='ignore').strip()
                     self.append_log_output(f"[{label}] {line}")

            stdout_task = asyncio.create_task(stream_reader(process.stdout, "Hayabusa"))
            stderr_task = asyncio.create_task(stream_reader(process.stderr, "Hayabusa-ERR"))

            async def tail_csv_and_analyze(csv_file_path):
                wait_start = asyncio.get_event_loop().time()
                while not os.path.exists(csv_file_path):
                    if asyncio.get_event_loop().time() - wait_start > 30: # 30 second timeout
                        self.append_log_output(f"[!] Timeout waiting for CSV file: {csv_file_path}")
                        return
                    await asyncio.sleep(0.1)

                seen = set()
                last_read_pos = 0
                while True:
                    try:
                        async with aiofiles.open(csv_file_path, mode='r', encoding='utf-8', errors='ignore') as f:
                            await f.seek(last_read_pos)
                            new_content = await f.read()
                            last_read_pos = await f.tell()

                            if new_content:
                                # Process only the new lines
                                reader = csv.DictReader(new_content.splitlines())
                                for row in reader:
                                    key_fields = (row.get('Timestamp'), row.get('EventID'), row.get('RuleTitle'), row.get('Details'))
                                    row_key = hash(key_fields)
                                    if row_key not in seen:
                                        seen.add(row_key)
                                        level = row.get('Level', '').lower()
                                        if level in ('critical', 'crit'):
                                            channel = row.get('Channel', 'N/A')
                                            event_id = row.get('EventID', 'N/A')
                                            rule_title = row.get('RuleTitle', 'N/A')
                                            details = row.get('Details', 'N/A')
                                            computer = row.get('Computer', 'N/A')
                                            timestamp = row.get('Timestamp', 'N/A')

                                            # Call the notifier (ensure it's safe)
                                            try:
                                                notify_user_hayabusa_critical(
                                                    event_log=f"{channel} (EID: {event_id})",
                                                    rule_title=rule_title,
                                                    details=details,
                                                    computer=computer,
                                                )
                                            except Exception as notify_err:
                                                 logger.error(f"Error calling Hayabusa notifier: {notify_err}")

                                            self.append_log_output(
                                                f"[!] LIVE CRITICAL [{timestamp}]: "
                                                f"{rule_title} | {computer} "
                                                f"| {channel} | {details[:100]}"
                                            )
                    except FileNotFoundError:
                        self.append_log_output(f"[!] CSV file disappeared: {csv_file_path}")
                        await asyncio.sleep(1)
                    except Exception as e:
                        self.append_log_output(f"[!] CSV tail error: {str(e)}")
                        await asyncio.sleep(1) # Prevent tight loop on error

                    # Check if Hayabusa process is still running
                    if process.returncode is not None:
                        self.append_log_output("[*] Hayabusa process finished. Stopping CSV tail.")
                        break
                    await asyncio.sleep(1.0) # Check file every second

            csv_tail_task = asyncio.create_task(tail_csv_and_analyze(output_file))
            self.append_log_output("[*] Hayabusa live monitoring started.")

            # Wait for the process itself to finish
            return_code = await process.wait()
            # Wait for stream readers to finish processing any remaining output
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

            if return_code == 0:
                self.append_log_output("[+] Hayabusa process completed successfully.")
            else:
                self.append_log_output(f"[!] Hayabusa process failed (code {return_code})")

        except asyncio.CancelledError:
            self.append_log_output("[!] Hayabusa task cancelled.")
        except Exception as e:
            self.append_log_output(f"[!] Error running Hayabusa live timeline: {traceback.format_exc()}")
        finally:
             # Cleanup: Cancel tailer, terminate process if still running
             if csv_tail_task and not csv_tail_task.done():
                 csv_tail_task.cancel()
                 try: await csv_tail_task
                 except asyncio.CancelledError: pass
             if process and process.returncode is None:
                 try:
                     process.terminate()
                     await process.wait()
                 except ProcessLookupError: pass # Already gone
                 except Exception as term_ex:
                     self.append_log_output(f"[!] Error terminating Hayabusa: {term_ex}")


    def _update_definitions_sync(self):
        """Synchronous (blocking) function to update ClamAV definitions."""
        self.append_log_output("[*] Checking virus definitions...")
        try:
            needs_update = False
             # Check if freshclam exists
            if not os.path.exists(freshclam_path):
                 self.append_log_output(f"[!] Error: freshclam not found at '{freshclam_path}'. Cannot update.")
                 return False # Indicate failure

            # Check definition file dates
            if not clamav_file_paths:
                 logger.warning("ClamAV definition file paths are not configured.")
                 needs_update = True # Assume update needed if paths missing
            else:
                for file_path in clamav_file_paths:
                    if os.path.exists(file_path):
                        file_mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if (datetime.now() - file_mod_time) > timedelta(hours=12):
                            needs_update = True
                            break
                    else: # If a definition file doesn't exist, update needed.
                        needs_update = True
                        break

            if needs_update:
                self.append_log_output("[*] Definitions are outdated or missing. Starting update...")
                # Run freshclam - use Popen for better control/non-blocking read potentially
                process = subprocess.Popen([freshclam_path],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True, encoding="utf-8", errors="ignore")
                stdout, stderr = process.communicate() # Wait for process to finish

                # Append stdout line by line
                if stdout:
                     self.append_log_output("--- Freshclam Output ---")
                     for line in stdout.splitlines():
                          self.append_log_output(line)
                     self.append_log_output("------------------------")
                # Append stderr line by line
                if stderr:
                     self.append_log_output("--- Freshclam Errors ---")
                     for line in stderr.splitlines():
                          self.append_log_output(f"[!] {line}")
                     self.append_log_output("------------------------")


                if process.returncode == 0:
                    self.append_log_output("[+] Reloading ClamAV database...")
                    reload_clamav_database() # This is blocking, run via to_thread
                    self.append_log_output("[+] Virus definitions updated successfully and ClamAV reloaded.")
                    return True # Indicate success
                else:
                    self.append_log_output(f"[!] Failed to update ClamAV definitions (freshclam exit code: {process.returncode}).")
                    return False # Indicate failure
            else:
                self.append_log_output("[*] Definitions are already up-to-date.")
                return True # Indicate success (no update needed)
        except Exception as e:
            self.append_log_output(f"[!] Error updating definitions: {str(e)}")
            logger.exception("Exception during definition update")
            return False # Indicate failure


    def _update_hayabusa_rules_sync(self):
        """Synchronous (blocking) function to update Hayabusa rules."""
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
        except Exception as e:
            self.append_log_output(f"[!] Error updating Hayabusa rules: {str(e)}")
            logger.exception("Exception during Hayabusa rule update")
            return False

    # --- Button Click Handlers ---

    @asyncSlot()
    async def on_update_definitions_clicked(self):
        """Handler for the 'Update Definitions' button click."""
        await self.run_task(
            'update_definitions',
            self._update_definitions_sync,
            is_async=False # This function is blocking
        )

    @asyncSlot()
    async def on_update_hayabusa_rules_clicked(self):
        """Handler for the 'Update Hayabusa Rules' button click."""
        await self.run_task(
            'update_hayabusa_rules',
            self._update_hayabusa_rules_sync,
            is_async=False # This function is blocking
        )


    # --- Startup ---

    @asyncSlot()
    async def run_startup_tasks(self):
        """Runs initial startup tasks asynchronously."""
        self.append_log_output("[*] Initializing...")
        # Start real-time protection task
        asyncio.create_task(self.run_task(
            'real_time_protection',
            self._run_real_time_protection_task,
            is_async=True
        ))
        # Start Hayabusa live monitoring task
        asyncio.create_task(self.run_task(
            'hayabusa_live',
            self._run_hayabusa_live_task,
            is_async=True
        ))
        self.append_log_output("[*] Startup tasks launched.")


    # --- UI Page Switching ---

    @asyncSlot(int)
    async def switch_page_with_animation(self, index):
        if (self.animation_group.state() == QParallelAnimationGroup.State.Running or
            self.main_stack.currentIndex() == index):
            return

        current_widget = self.main_stack.currentWidget()
        next_widget = self.main_stack.widget(index)
        current_index = self.main_stack.currentIndex()

        # Simple Fade Animation (Slide can be complex with async)
        current_opacity_anim = QPropertyAnimation(current_widget, b"windowOpacity")
        current_opacity_anim.setDuration(250)
        current_opacity_anim.setStartValue(1.0)
        current_opacity_anim.setEndValue(0.0)
        current_opacity_anim.finished.connect(current_widget.hide) # Hide after fade

        next_opacity_anim = QPropertyAnimation(next_widget, b"windowOpacity")
        next_opacity_anim.setDuration(250)
        next_opacity_anim.setStartValue(0.0)
        next_opacity_anim.setEndValue(1.0)

        # Set widget index *before* starting fade-in
        next_widget.setWindowOpacity(0.0) # Start transparent
        self.main_stack.setCurrentIndex(index)
        next_widget.show()
        next_widget.raise_()

        self.animation_group = QParallelAnimationGroup()
        self.animation_group.addAnimation(current_opacity_anim)
        self.animation_group.addAnimation(next_opacity_anim)

        # Connect finished signal properly
        self.animation_group.finished.connect(self._on_animation_finished)
        self.animation_group.start()

    def _on_animation_finished(self):
         # Ensure final opacity is 1.0 for the current widget
         current_widget = self.main_stack.currentWidget()
         if current_widget:
             current_widget.setWindowOpacity(1.0)
         # Clean up animation group? Not strictly necessary unless reusing heavily.

    # --- Window Event Handlers ---

    def closeEvent(self, event):
        # Prevent closing, just hide
        event.ignore()
        self.hide()
        self.append_log_output("[*] Application minimized (window hidden)")

    # --- UI Creation Methods ---

    def create_status_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(30)

        # Main status area
        main_area = QHBoxLayout()
        main_area.setSpacing(40)

        self.shield_widget = ShieldWidget()
        main_area.addWidget(self.shield_widget, 2) # Give shield more space

        status_vbox = QVBoxLayout()
        status_vbox.addStretch()

        title = QLabel("System Status")
        title.setObjectName("page_title")
        self.status_text = QLabel("Initializing...") # Start with initializing text
        self.status_text.setObjectName("page_subtitle_busy") # Use busy style initially

        version_label = QLabel(WINDOW_TITLE)
        version_label.setObjectName("version_label")
        # Store defs_label to update it later
        self.defs_label = QLabel(get_latest_clamav_def_time()) # Get initial time
        self.defs_label.setObjectName("version_label")

        status_vbox.addWidget(title)
        status_vbox.addWidget(self.status_text)
        status_vbox.addSpacing(30)
        status_vbox.addWidget(version_label)
        status_vbox.addWidget(self.defs_label)
        status_vbox.addStretch()

        main_area.addLayout(status_vbox, 3) # Give text more space
        layout.addLayout(main_area)
        layout.addStretch() # Add stretch at the bottom


        self.log_outputs.append(None) # No log widget on status page
        return page

    def create_task_page(self, title_text, main_task_name, main_button_text, additional_tasks=None):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        # Store buttons for enabling/disabling
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

        # Main button setup
        main_button = QPushButton(main_button_text)
        main_button.setObjectName("action_button")
        self.task_buttons[main_task_name] = main_button # Store button reference

        # Determine if main task is sync or async and connect appropriately
        if main_task_name == 'update_definitions':
             main_button.clicked.connect(self.on_update_definitions_clicked)
        elif main_task_name == 'update_hayabusa_rules':
             main_button.clicked.connect(self.on_update_hayabusa_rules_clicked)
        # Add other specific task connections here if needed
        else:
             logger.warning(f"No specific handler for main task: {main_task_name}")
             main_button.setEnabled(False) # Disable if no handler

        button_container.addWidget(main_button)

        # Additional buttons
        if additional_tasks:
            for btn_text, task_info in additional_tasks.items():
                task_name = task_info['name']
                is_async = task_info['is_async']
                func = task_info['func']

                extra_btn = QPushButton(btn_text)
                extra_btn.setObjectName("action_button")
                self.task_buttons[task_name] = extra_btn # Store button

                # Connect based on whether the target is sync or async
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
        layout.addWidget(log_output, 1) # Give log area expansion priority

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
             "HydraDragon Antivirus - Open Source Antvirus with Advanced Real-Time Protection."
        )
        about_text.setWordWrap(True)
        about_text.setStyleSheet("font-size: 15px; line-height: 1.6;") # Slightly larger text
        layout.addWidget(about_text)

        buttons_layout = QHBoxLayout() # Use QHBoxLayout for horizontal buttons
        buttons_layout.setSpacing(15)

        github_button = QPushButton("View on GitHub")
        github_button.setObjectName("action_button")
        github_button.clicked.connect(lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus"))
        buttons_layout.addWidget(github_button)

        buttons_layout.addStretch() # Push buttons to the left

        layout.addLayout(buttons_layout)
        layout.addStretch() # Push content upwards

        self.log_outputs.append(None) # No log output on About page
        return page

    def create_main_content(self):
        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self.create_status_page())

        # Define additional tasks for the Update page
        update_additional_tasks = {
             "Update Hayabusa Rules": {
                 'name': 'update_hayabusa_rules',
                 'is_async': False, # It's a blocking sync function
                 'func': self._update_hayabusa_rules_sync
             }
         }

        self.main_stack.addWidget(self.create_task_page(
            "Updates",
            main_task_name='update_definitions', # Task name for the main button
            main_button_text="Update ClamAV Definitions",
            additional_tasks=update_additional_tasks
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

        icon_widget = HydraIconWidget(sidebar_frame) # Pass parent
        icon_widget.setFixedSize(40, 40) # Slightly larger icon

        logo_label = QLabel("HYDRA")
        logo_label.setObjectName("logo")

        logo_area.addWidget(icon_widget)
        logo_area.addWidget(logo_label)
        logo_area.addStretch()

        sidebar_layout.addLayout(logo_area)
        sidebar_layout.addSpacing(30)

        nav_buttons = [
            ("🏠", "Status"),
            ("🔄", "Updates"), # Changed name
            ("ℹ️", "About") # Use a standard info icon
        ]

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        for i, (icon, name) in enumerate(nav_buttons):
            button = QPushButton(f"{icon}  {name}")
            button.setCheckable(True)
            button.setObjectName("nav_button")
            # Connect using asyncSlot correctly
            button.clicked.connect(lambda checked=False, index=i: asyncio.create_task(self.switch_page_with_animation(index)))

            sidebar_layout.addWidget(button)
            self.nav_group.addButton(button, i)

        # Check the first button initially
        first_button = self.nav_group.button(0)
        if first_button:
             first_button.setChecked(True)

        sidebar_layout.addStretch()

        # Add version/status at the bottom
        version_label_side = QLabel(f"Version: {WINDOW_TITLE.split('v')[-1] if 'v' in WINDOW_TITLE else 'N/A'}")
        version_label_side.setStyleSheet("color: #6A7384; font-size: 11px; padding: 0 10px;")
        sidebar_layout.addWidget(version_label_side)


        return sidebar_frame

    def setup_ui(self):
        if os.path.exists(icon_path):
             try:
                 self.setWindowIcon(QIcon(icon_path))
             except Exception as e:
                  logger.error(f"Failed to set window icon from {icon_path}: {e}")
        else:
            logger.error(f"Icon file not found at: {icon_path}")

        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(1100, 800)
        self.resize(1400, 900)

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self.create_sidebar())
        main_layout.addWidget(self.create_main_content(), 1) # Main content takes more space

def main():
    try:
        app = QApplication(sys.argv)

        # --- qasync setup ---
        loop = QEventLoop(app)
        asyncio.set_event_loop(loop)

        window = AntivirusApp()
        window.show()

        # --- Start the event loop ---
        with loop:
            logger.info("Starting asyncio event loop...")
            loop.run_forever()

    except Exception as e:
        logger.critical(f"Critical error during application startup: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    # Ensure logs directory exists
    try:
        os.makedirs(log_directory, exist_ok=True)
    except Exception as e:
        print(f"Error creating log directory {log_directory}: {e}", file=sys.stderr)

    logger.info(f"HydraDragon Engine starting up...")
    logger.info(f"Log directory: {log_directory}")
    logger.info(f"Working directory: {main_dir}")

    main()
