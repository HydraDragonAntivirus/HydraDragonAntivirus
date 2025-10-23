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
        try:
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
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
                painter.save()
                try:
                    painter.translate(self.width() / 2 - 15, self.height() / 2 - 10)
                    # ... fallback drawing here ...
                finally:
                    painter.restore()
        except Exception:
            logger.exception("Exception in HydraIconWidget.paintEvent")
        finally:
            # ensure QPainter is properly ended to avoid QBackingStore::endPaint() error
            try:
                if painter.isActive():
                    painter.end()
            except Exception:
                logger.exception("Error ending painter in HydraIconWidget.paintEvent")

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
        painter = QPainter(self)
        try:
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
            logger.exception("Exception in ShieldWidget.paintEvent")
        finally:
            try:
                if painter.isActive():
                    painter.end()
            except Exception:
                logger.exception("Error ending painter in ShieldWidget.paintEvent")
        
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
        self.setup_ui()

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
                if log_widget and isinstance(log_widget, QTextEdit):
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
                # shield_widget.set_status is lightweight and debounced in ShieldWidget
                self.shield_widget.set_status(bool(is_protected))
            if hasattr(self, 'status_text'):
                if is_protected:
                    self.status_text.setText("System protected!")
                    self.status_text.setObjectName("page_subtitle")
                else:
                    self.status_text.setText("System busy...")
                    self.status_text.setObjectName("page_subtitle_busy")
                # Force style refresh
                self.status_text.setStyle(self.style())
        except Exception:
            logger.exception("Error in _on_status_signal")

    def _on_progress_signal(self, value: float):
        """Receive progress updates (0.0..1.0). We use it to update shield progress or other UI."""
        try:
            if hasattr(self, 'shield_widget') and self.shield_widget:
                # ShieldWidget implements set_check_progress defensively
                self.shield_widget.set_check_progress(float(value))
            # Optionally show progress in a progress bar if you add one
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
            # Format timestamped log optionally
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            formatted = f"{timestamp} {text}"
            # Send to UI
            self.log_signal.emit(formatted)
            # Also mirror to logger
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
        """Update UI when a task starts. This runs on the Qt thread (since run_task is scheduled from qasync)."""
        try:
            self.append_log_output(f"[*] Task '{task_name}' started.")
            # Mark shield busy via signal to ensure main-thread execution
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
            if task_name in self.active_tasks:
                # removed elsewhere after run
                pass
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
        """Run an async coroutine or blocking function on a background thread, with UI updates marshalled through signals."""
        if task_name in self.active_tasks:
            self.append_log_output(f"[*] Task '{task_name}' already running.")
            return

        self.active_tasks.add(task_name)
        # UI update should be scheduled on Qt main thread
        QTimer.singleShot(0, lambda: self._update_ui_for_task_start(task_name))

        try:
            if is_async:
                # Directly await coroutine
                await coro_or_func(*args)
            else:
                # Offload blocking function to a thread
                await asyncio.to_thread(coro_or_func, *args)
        except asyncio.CancelledError:
            self.append_log_output(f"[!] Task '{task_name}' was cancelled.")
            logger.info(f"Task {task_name} cancelled.")
        except Exception:
            error_msg = f"[!] Error in task '{task_name}': {traceback.format_exc()}"
            self.append_log_output(error_msg)
            logger.exception(f"Exception in task {task_name}")
        finally:
            if task_name in self.active_tasks:
                self.active_tasks.remove(task_name)
            # Update UI end on Qt main thread
            QTimer.singleShot(0, lambda: self._update_ui_for_task_end(task_name))

    # ---------------------------
    # Specific tasks (adapted from your original code)
    # ---------------------------
    async def _run_real_time_protection_task(self):
        """Run the real-time protection async generator; append outputs to logs."""
        self.append_log_output("[*] Real-time protection monitoring starting...")
        try:
            # It's expected to be an async generator
            async for output in run_real_time_protection_with_yield_async():
                try:
                    # If the generator yields progress-like messages, you can parse and emit progress_signal
                    # Example heuristic: if output includes 'progress:' extract float 0..1
                    if isinstance(output, str) and "progress:" in output:
                        try:
                            # naive parse: "progress:0.42" or "progress: 42%"
                            token = output.split("progress:")[-1].strip()
                            if token.endswith('%'):
                                val = float(token.rstrip('%')) / 100.0
                            else:
                                val = float(token)
                            self.progress_signal.emit(max(0.0, min(1.0, val)))
                        except Exception:
                            # ignore parsing errors
                            pass
                    # Append full output to logs
                    self.append_log_output(str(output))
                except Exception:
                    logger.exception("Error handling output from real-time protection generator")
            self.append_log_output("[+] Real-time protection monitoring finished.")
        except asyncio.CancelledError:
            self.append_log_output("[!] Real-time protection task cancelled.")
            logger.info("Real-time protection task cancelled")
            return
        except Exception:
            self.append_log_output(f"[!] Error during real-time protection: {traceback.format_exc()}")
            logger.exception("Unhandled exception in real-time protection")

    async def _run_hayabusa_live_task(self):
        """Async wrapper to run Hayabusa csv-timeline and tail the output for critical events."""
        self.append_log_output("[*] Starting Hayabusa live timeline analysis...")
        process = None
        csv_tail_task = None
        try:
            if not os.path.exists(hayabusa_path):
                self.append_log_output(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_live_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"hayabusa_live_{timestamp}.csv")

            cmd = [hayabusa_path, "csv-timeline", "-l", "-o", output_file, "--profile", "standard", "-m", "critical"]
            self.append_log_output(f"[*] Running command: {' '.join(cmd)}")

            process = await asyncio.create_subprocess_exec(
                *cmd,
                cwd=os.path.dirname(hayabusa_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            async def stream_reader(pipe, label):
                if pipe is None:
                    return
                while True:
                    line_bytes = await pipe.readline()
                    if not line_bytes:
                        break
                    line = line_bytes.decode('utf-8', errors='ignore').strip()
                    self.append_log_output(f"[{label}] {line}")

            stdout_task = asyncio.create_task(stream_reader(process.stdout, "Hayabusa"))
            stderr_task = asyncio.create_task(stream_reader(process.stderr, "Hayabusa-ERR"))

            async def tail_csv_and_analyze(csv_file_path):
                wait_start = asyncio.get_event_loop().time()
                while not os.path.exists(csv_file_path):
                    if asyncio.get_event_loop().time() - wait_start > 30:
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
                                            # Notify safely (not a UI call)
                                            try:
                                                from hydradragon.antivirus_scripts.notify_user import notify_user_hayabusa_critical
                                                notify_user_hayabusa_critical(
                                                    event_log=f"{channel} (EID: {event_id})",
                                                    rule_title=rule_title,
                                                    details=details,
                                                    computer=computer,
                                                )
                                            except Exception:
                                                logger.exception("Error calling Hayabusa notifier")

                                            self.append_log_output(
                                                f"[!] LIVE CRITICAL [{timestamp}]: {rule_title} | {computer} | {channel} | {details[:100]}"
                                            )
                    except FileNotFoundError:
                        self.append_log_output(f"[!] CSV file disappeared: {csv_file_path}")
                        await asyncio.sleep(1)
                    except asyncio.CancelledError:
                        self.append_log_output("[!] CSV tail task cancelled")
                        return
                    except Exception:
                        self.append_log_output(f"[!] CSV tail error: {traceback.format_exc()}")
                        await asyncio.sleep(1)

                    # stop when hayabusa process ends
                    if process.returncode is not None:
                        self.append_log_output("[*] Hayabusa process finished. Stopping CSV tail.")
                        break
                    await asyncio.sleep(1.0)

            csv_tail_task = asyncio.create_task(tail_csv_and_analyze(output_file))
            self.append_log_output("[*] Hayabusa live monitoring started.")

            return_code = await process.wait()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

            if return_code == 0:
                self.append_log_output("[+] Hayabusa process completed successfully.")
            else:
                self.append_log_output(f"[!] Hayabusa process failed (code {return_code})")

        except asyncio.CancelledError:
            self.append_log_output("[!] Hayabusa task cancelled.")
            logger.info("Hayabusa live task cancelled")
            return
        except Exception:
            self.append_log_output(f"[!] Error running Hayabusa live timeline: {traceback.format_exc()}")
            logger.exception("Hayabusa live task error")
        finally:
            if csv_tail_task and not csv_tail_task.done():
                csv_tail_task.cancel()
                try:
                    await csv_tail_task
                except asyncio.CancelledError:
                    pass
            if process and process.returncode is None:
                try:
                    process.terminate()
                    await process.wait()
                except Exception:
                    logger.exception("Error terminating Hayabusa process")

    def _update_definitions_sync(self):
        """Blocking freshclam call executed in a thread via run_task(is_async=False)."""
        self.append_log_output("[*] Checking virus definitions...")
        try:
            if not os.path.exists(freshclam_path):
                self.append_log_output(f"[!] Error: freshclam not found at '{freshclam_path}'. Cannot update.")
                return False

            needs_update = False
            if not clamav_file_paths:
                logger.warning("ClamAV definition file paths are not configured.")
                needs_update = True
            else:
                for file_path in clamav_file_paths:
                    if os.path.exists(file_path):
                        file_mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                        if (datetime.now() - file_mod_time) > timedelta(hours=12):
                            needs_update = True
                            break
                    else:
                        needs_update = True
                        break

            if needs_update:
                self.append_log_output("[*] Definitions are outdated or missing. Starting update...")
                process = subprocess.Popen([freshclam_path],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           text=True, encoding="utf-8", errors="ignore")
                stdout, stderr = process.communicate()

                if stdout:
                    self.append_log_output("--- Freshclam Output ---")
                    for line in stdout.splitlines():
                        self.append_log_output(line)
                    self.append_log_output("------------------------")
                if stderr:
                    self.append_log_output("--- Freshclam Errors ---")
                    for line in stderr.splitlines():
                        self.append_log_output(f"[!] {line}")
                    self.append_log_output("------------------------")

                if process.returncode == 0:
                    self.append_log_output("[+] Reloading ClamAV database...")
                    try:
                        reload_clamav_database()
                        self.append_log_output("[+] Virus definitions updated successfully and ClamAV reloaded.")
                        return True
                    except Exception:
                        logger.exception("reload_clamav_database failed")
                        return False
                else:
                    self.append_log_output(f"[!] Failed to update ClamAV definitions (freshclam exit code: {process.returncode}).")
                    return False
            else:
                self.append_log_output("[*] Definitions are already up-to-date.")
                return True
        except Exception:
            self.append_log_output(f"[!] Error updating definitions: {traceback.format_exc()}")
            logger.exception("Exception during definition update")
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
    # Startup
    # ---------------------------
    @asyncSlot()
    async def run_startup_tasks(self):
        self.append_log_output("[*] Initializing...")
        # start real-time protection
        asyncio.create_task(self.run_task('real_time_protection', self._run_real_time_protection_task, is_async=True))
        # hayabusa live
        asyncio.create_task(self.run_task('hayabusa_live', self._run_hayabusa_live_task, is_async=True))
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

        nav_buttons = [("🏠", "Status"), ("🔄", "Updates"), ("ℹ️", "About")]

        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        for i, (icon, name) in enumerate(nav_buttons):
            button = QPushButton(f"{icon}  {name}")
            button.setCheckable(True)
            button.setObjectName("nav_button")
            # Use lambda capturing index safely
            button.clicked.connect(lambda checked=False, idx=i: asyncio.create_task(self.switch_page_with_animation(idx)))
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

    def setup_ui(self):
        try:
            if os.path.exists(icon_path):
                try:
                    self.setWindowIcon(QIcon(icon_path))
                except Exception:
                    logger.exception("Failed to set window icon")
            else:
                logger.debug(f"Icon file not found at: {icon_path}")
        except Exception:
            logger.exception("setup_ui: icon handling failed")

        self.setWindowTitle(WINDOW_TITLE)
        self.setMinimumSize(1100, 800)
        self.resize(1400, 900)

        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self.create_sidebar())
        main_layout.addWidget(self.create_main_content(), 1)

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
        # Fallback to stderr if logger isn't ready yet
        print(f"Error creating log directory {log_directory}: {e}", file=sys.stderr)

    # Top-level startup guarded so uncaught exceptions in main() are logged
    try:
        logger.info("HydraDragon Engine starting up...")
        logger.info(f"Log directory: {log_directory}")
        logger.info(f"Working directory: {main_dir}")

        main()
    except Exception:
        # Log full traceback and exit with non-zero code
        try:
            logger.critical("Unhandled exception in main():\n" + traceback.format_exc())
        except Exception:
            # If logger itself is broken, print to stderr as a last resort
            print("Unhandled exception in main():", file=sys.stderr)
            print(traceback.format_exc(), file=sys.stderr)
        sys.exit(1)
