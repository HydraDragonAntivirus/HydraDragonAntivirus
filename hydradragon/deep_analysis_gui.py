import sys
import os
import threading
import time
import webbrowser
import shutil
import json
import subprocess
import difflib

# Ensure the script's directory is the working directory
main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)

# Add the main directory to sys.path to allow absolute imports
if main_dir not in sys.path:
    sys.path.insert(0, main_dir)

from datetime import datetime, timedelta
from typing import Optional
from hydra_logger import (
    logger,
    setup_gui_mode,
    get_alert_counts,
    application_log_file,
    log_directory,
    script_dir,
    reinitialize_hydra_logger
)
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QProgressBar,
                               QPushButton, QLabel, QTextEdit, QGraphicsDropShadowEffect,
                               QFrame, QStackedWidget, QLineEdit,
                               QApplication, QButtonGroup, QGroupBox, QFileDialog)
from PySide6.QtCore import (Qt, QPropertyAnimation, QEasingCurve, QThread,
                            Signal, QPoint, QParallelAnimationGroup, Property, QRect, QTimer)
from PySide6.QtGui import (QColor, QPainter, QBrush, QLinearGradient, QPen,
                           QPainterPath, QRadialGradient, QIcon, QPixmap)
from hydradragon.antivirus_scripts.antivirus import (
    icon_path, 
    meta_llama_1b_dir, 
    freshclam_path,
    clamav_file_paths, 
    sandboxie_path, 
    sandboxie_box, 
    reports_dir,                      
    run_analysis_with_yield,
    scan_code_for_links,
    run_sandboxie_plugin_script,
    get_sandbox_path,
    scan_report_path,
    run_sandboxie_control,
    reload_clamav_database,
    restart_owlyshield_threaded,
    stop_suricata,
    run_suricata,
    is_suricata_running,
    reset_flags,
    clear_pe_cache,
    av_events_json_file_path,
    remove_log_file,
    MANAGED_DIRECTORIES,
    get_latest_clamav_def_time,
    WINDOW_TITLE,
    hayabusa_path,
    evtx_logs_path,
    run_hydra_whitelist,
    run_and_copy_log,
    parse_report,
    scan_file_with_meta_llama,
    stdout_console_log_file,
    stderr_console_log_file
)

# ----- Global Variables to hold captured data -----
pre_analysis_log_path = None
post_analysis_log_path = None
pre_analysis_entries = None
post_analysis_entries = None

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
        self.stop_requested = False

    def request_stop(self):
        """Public method to request stopping the worker"""
        self.stop_requested = True
    # --- Task-Specific Methods (Called by run()) ---

    def load_meta_llama_1b_model(self):
        """
        Function to load Meta Llama-3.2-1B model and tokenizer.
        This is a resource-intensive operation.
        Checks that the local folder exists before attempting to load.
        """
        # Check if the local model directory exists
        if not os.path.isdir(meta_llama_1b_dir):
            logger.error(f"Meta Llama-3.2-1B directory not found: {meta_llama_1b_dir}")
            return None, None

        # --- Hugging Face Transformers for Llama model (Optional Feature) ---
        # This feature is experimental and requires significant RAM.
        try:
            from transformers import AutoTokenizer, AutoModelForCausalLM
        except Exception as ex:
            error_message = f"Error importing transformers: {ex}"
            logger.error(error_message)
            return None, None

        try:
            logger.info("Attempting to load Llama-3.2-1B model and tokenizer...")

            # Load tokenizer and model from the local directory
            llama32_tokenizer = AutoTokenizer.from_pretrained(
                meta_llama_1b_dir,
                local_files_only=True
            )
            llama32_model = AutoModelForCausalLM.from_pretrained(
                meta_llama_1b_dir,
                local_files_only=True,
                # Optional: Add device_map="auto" if you have a GPU and want to use it
            )

            logger.info("Llama-3.2-1B successfully loaded!")
            return llama32_model, llama32_tokenizer
        except Exception as ex:
            error_message = f"Error loading Llama-3.2-1B model or tokenizer: {ex}"
            logger.error(error_message)
            return None, None

    def generate_whitelist_db(self, optional_path: Optional[str] = None):
        """
        Wrapper to generate whitelist from within a class (emits UI signal).
        If optional_path is provided, it will be used as the output file for the whitelist.
        """
        success = run_hydra_whitelist(optional_path)
        msg = "[+] whitelist (whitelist_hashes.txt) generated." if success else "[!] Failed to generate whitelist (whitelist_hashes.txt)."
        self.output_signal.emit(msg)

    def capture_analysis_logs(self):
        global pre_analysis_log_path, post_analysis_log_path, pre_analysis_entries, post_analysis_entries
        if pre_analysis_log_path is None:
            path = run_and_copy_log(label="pre")
            pre_analysis_log_path = path
            pre_analysis_entries = parse_report(path)
            self.output_signal.emit(f"[+] Pre-analysis log captured. Don't forget to capture the post-analysis logger.: {os.path.basename(path)}")
        elif post_analysis_log_path is None:
            path = run_and_copy_log(label="post")
            post_analysis_log_path = path
            post_analysis_entries = parse_report(path)
            self.output_signal.emit(f"[+] Post-analysis log captured: {os.path.basename(path)}")
        else:
            self.output_signal.emit("[!] Both pre and post-analysis captures have already been completed.")

    def compare_analysis_logs(self):
        if not pre_analysis_log_path or not post_analysis_log_path:
            self.output_signal.emit("[!] Please capture both pre and post-analysis logs first!")
            return
        try:
            with open(pre_analysis_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                pre_lines = f.readlines()
            with open(post_analysis_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                post_lines = f.readlines()

            diff = difflib.ndiff(pre_lines, post_lines)
            filtered_diff = [line for line in diff if line.startswith(('+', '-'))]

            diff_file_path = os.path.join(log_directory, 'HiJackThis_diff.log')
            with open(diff_file_path, 'w', encoding='utf-8') as df:
                df.writelines(filtered_diff)
            self.output_signal.emit(f"[+] Diff log created at: {diff_file_path}")

            llama_response = scan_file_with_meta_llama(diff_file_path, HiJackThis_flag=True)
            self.output_signal.emit("\n[*] Llama analysis of the diff log:")
            self.output_signal.emit(llama_response)

        except Exception as e:
            self.output_signal.emit(f"[!] Error comparing logs: {str(e)}")

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

    def analyze_file_worker(self, file_path):
        """
        Runs file analysis in a separate thread without freezing.
        Results or errors are emitted via output_signal.
        """

        if self.stop_requested:
            self.output_signal.emit("[!] Analysis stopped by user request")
            return

        self.output_signal.emit(f"[*] Starting analysis for: {file_path}")

        # Stop callback
        def check_stop():
            return self.stop_requested

        # Analysis task to run in a separate thread
        def analysis_task():
            try:
                result = run_analysis_with_yield(file_path, stop_callback=check_stop)
                if not self.stop_requested:
                    self.output_signal.emit(result)
                    self.output_signal.emit("[+] File analysis completed successfully")
                else:
                    self.output_signal.emit("[!] Analysis stopped by user")
            except Exception as e:
                self.output_signal.emit(f"[!] Error during analysis: {str(e)}")
                logger.error(f"File analysis error: {str(e)}")

        # Start analysis in a background thread - fully non-blocking
        threading.Thread(target=analysis_task).start()

    def scan_network_indicators(self, network_indicators: list):
        """
        Scan the already extracted network indicators using the existing scanning functions.
        """
        try:
            self.output_signal.emit(f"\n[*] Scanning {len(network_indicators)} network indicators...")

            for indicator in network_indicators:
                # Assuming indicator is a string (URL, IP, domain, etc.)
                self.output_signal.emit(f"[*] Scanning indicator: {indicator}")

                # Create mock decompiled code containing the indicator
                mock_code = f"Network indicator from rootkit scan: {indicator}"

                # Use the existing scan_code_for_links function with registry_flag=True
                scan_code_for_links(
                    mock_code,
                    "registry_indicator",
                    registry_flag=True
                )

        except Exception as e:
            logger.error(f"Error scanning network indicators: {str(e)}")
            self.output_signal.emit(f"[!] Error scanning network indicators: {str(e)}")

    def check_and_scan_network_indicators(self):
        """
        Check for network indicators file and scan the indicators only if file exists.
        """
        try:
            network_indicators_path = os.path.join(reports_dir, "network_indicators_for_av.json")

            # Only proceed if network indicators file exists
            if os.path.exists(network_indicators_path):
                self.output_signal.emit(f"[*] Found network indicators file: {network_indicators_path}")

                # Load network indicators from file
                with open(network_indicators_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)

                # Extract indicators from the JSON structure
                if 'indicators' in data:
                    file_indicators = data['indicators']
                    if isinstance(file_indicators, list) and file_indicators:
                        self.output_signal.emit(f"[+] Loaded {len(file_indicators)} network indicators from file")
                        self.scan_network_indicators(file_indicators)
                    else:
                        self.output_signal.emit("[!] No indicators found in the file")
                else:
                    self.output_signal.emit("[!] Invalid network indicators file format")
            # No message if file doesn't exist - just silently skip

        except Exception as e:
            logger.error(f"Error checking network indicators: {str(e)}")
            self.output_signal.emit(f"[!] Error checking network indicators: {str(e)}")

    def perform_rootkit_scan(self):
        """
        Runs the rootkit scan script and displays the report.
        """
        try:
            self.output_signal.emit("[*] Starting Rootkit Scan via Sandboxie Plugin...")
            run_sandboxie_plugin_script()  # This creates the report file

            # Get the path to the generated report
            sandbox_scan_report_path = get_sandbox_path(scan_report_path)
            self.output_signal.emit(f"[+] Rootkit scan finished. Report located at: {sandbox_scan_report_path}")

            if os.path.exists(sandbox_scan_report_path):
                with open(sandbox_scan_report_path, 'r', encoding='utf-8') as f:
                    report_content = f.read()
                self.output_signal.emit("\n--- Rootkit Scan Report ---")
                self.output_signal.emit(report_content)
                self.output_signal.emit("--- End of Report ---")
            else:
                self.output_signal.emit("[!] Error: Sandboxie report file was not found after the scan.")

            # Check for network indicators file and scan them if file exists
            self.check_and_scan_network_indicators()

        except Exception as e:
            self.output_signal.emit(f"[!] Error during rootkit scan: {str(e)}")

    def full_cleanup_sandbox(self):
        """
        Fully cleans up the Sandboxie environment by terminating and deleting the DefaultBox sandbox.
        """
        try:
            self.output_signal.emit("[*] Starting full sandbox cleanup using Start.exe termination commands...")
            cmds = [
                [sandboxie_path, "/terminate"],
                [sandboxie_path, f"/box:{sandboxie_box}", "/terminate"],
                [sandboxie_path, "/terminate_all"],
            ]
            for cmd in cmds:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    self.output_signal.emit(f"[!] Command {' '.join(cmd)} failed: {result.stderr.strip()}")
                else:
                    self.output_signal.emit(f"[+] Command {' '.join(cmd)} successful.")
                time.sleep(1)

            # Delete (cleanup) the DefaultBox sandbox
            cleanup_cmd = [sandboxie_path, "delete_sandbox"]
            result = subprocess.run(cleanup_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                self.output_signal.emit(f"[!] Sandbox delete command failed: {result.stderr.strip()}")
            else:
                self.output_signal.emit("[+] Sandbox 'DefaultBox' deleted successfully.")

        except Exception as ex:
            self.output_signal.emit(f"[!] Full sandbox cleanup encountered an exception: {ex}")

    def cleanup_directories(self):
        """
        Removes all the managed directories and their contents.
        """
        cleaned_count = 0
        for directory in MANAGED_DIRECTORIES:
            try:
                if os.path.exists(directory):
                    shutil.rmtree(directory)
                    self.output_signal.emit(f"[+] Cleaned directory: {directory}")
                    cleaned_count += 1
            except Exception as e:
                self.output_signal.emit(f"[!] Error cleaning directory {directory}: {str(e)}")

        self.output_signal.emit(f"[+] Total directories cleaned: {cleaned_count}")

    def restart_suricata(self):
        """Restart Suricata with proper status reporting"""
        # Restart Suricata
        self.output_signal.emit("[*] Starting Suricata...")

        try:
            success = run_suricata()
            if success:
                time.sleep(1)  # Brief wait for startup
                if is_suricata_running():
                    self.output_signal.emit("[+] Suricata started successfully.")
                else:
                    self.output_signal.emit("[!] Suricata startup uncertain - check logs.")
            else:
                self.output_signal.emit("[-] Failed to start Suricata - check logs.")
        except Exception as ex:
            self.output_signal.emit(f"[-] Suricata startup error: {ex}")

    def restart_services(self):
        """
        Restarts ClamAV and Suricata services.
        """
        try:
            # Restart ClamAV
            self.output_signal.emit("[*] Restarting Owlyshield and ClamAV wrapper...")
            reload_clamav_database()
            restart_owlyshield_threaded(stop_only=True)
            self.output_signal.emit("[+] Owlyshield stopped and ClamAV wrapper restarted.")

            # Stop Suricata and cleanup logs
            self.output_signal.emit("[*] Step 1: Stopping Suricata and cleaning logs...")
            stop_suricata()

            # Restart Suricata with proper status reporting
            self.restart_suricata()

        except Exception as e:
            self.output_signal.emit(f"[!] Error restarting services: {str(e)}")

    def recreate_directories(self):
        """
        Recreates all the managed directories after cleanup.
        """
        created_count = 0
        for directory in MANAGED_DIRECTORIES:
            try:
                # Skip log_directory as it shouldn't be recreated in the normal workflow
                if directory == log_directory:
                    continue

                os.makedirs(directory, exist_ok=True)
                created_count += 1
            except Exception as e:
                self.output_signal.emit(f"[!] Error creating directory {directory}: {str(e)}")

        self.output_signal.emit(f"[+] Total directories recreated: {created_count}")

    def cleanup_logging_files(self):
        """
        Stops logging and removes/cleans up log files.
        """
        try:
            # Get the main script directory
            log_directory = os.path.join(script_dir, "log")

            # Close current stdout/stderr redirections
            if hasattr(sys.stdout, 'close') and sys.stdout != sys.__stdout__:
                sys.stdout.close()
            if hasattr(sys.stderr, 'close') and sys.stderr != sys.__stderr__:
                sys.stderr.close()

            # Restore original stdout/stderr
            sys.stdout = sys.__stdout__
            sys.stderr = sys.__stderr__

            # Stop the logging handlers
            logger.shutdown()

            # Remove log files if they exist
            log_files = [stdout_console_log_file, stderr_console_log_file,
                         application_log_file]

            for log_file in log_files:
                if os.path.exists(log_file):
                    try:
                        os.remove(log_file)
                        self.output_signal.emit(f"[+] Removed log file: {log_file}")
                    except (OSError, PermissionError) as e:
                        self.output_signal.emit(f"[!] Could not remove {log_file}: {str(e)}")

            # Optionally remove the entire log directory if empty
            if os.path.exists(log_directory) and not os.listdir(log_directory):
                try:
                    os.rmdir(log_directory)
                    self.output_signal.emit(f"[+] Removed empty log directory: {log_directory}")
                except (OSError, PermissionError) as e:
                    self.output_signal.emit(f"[!] Could not remove log directory: {str(e)}")

            self.output_signal.emit("[+] Logging cleanup completed successfully!")

        except Exception as e:
            self.output_signal.emit(f"[!] Error during logging cleanup: {str(e)}")

    def reinitialize_logging(self):
        """
        Reinitializes logging after cleanup using hydra_logger.
        Keeps stdout/stderr redirection.
        """
        try:
            log_directory = os.path.join(script_dir, "log")
            os.makedirs(log_directory, exist_ok=True)

            # Define log file paths
            stdout_console_log_file = os.path.join(log_directory, "antivirusconsolestdout.log")
            stderr_console_log_file = os.path.join(log_directory, "antivirusconsolestderr.log")

            # --- Reset Hydra logger via hydra_logger.py ---
            reinitialize_hydra_logger()

            # --- Stdout/Stderr redirection ---
            sys.stdout = open(stdout_console_log_file, "w", encoding="utf-8", errors="ignore")
            sys.stderr = open(stderr_console_log_file, "w", encoding="utf-8", errors="ignore")

            # --- Log reinitialization event ---
            from datetime import datetime
            logger.info("Logging reinitialized at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            self.output_signal.emit("[+] Logging reinitialized successfully!")

        except Exception as e:
            self.output_signal.emit(f"[!] Error during logging reinitialization: {str(e)}")

    def perform_cleanup(self):
        """
        Performs comprehensive cleanup of the environment including logging files.
        """
        try:
            global pre_analysis_log_path, post_analysis_log_path, pre_analysis_entries, post_analysis_entries

            self.output_signal.emit("[*] Starting comprehensive environment cleanup...")

            # Step 1: Stop Snort and cleanup logs
            self.output_signal.emit("[*] Step 1: Stopping Suricata and cleaning logs...")
            stop_suricata()

            # Step 2: Cleanup Sandboxie
            self.output_signal.emit("[*] Step 2: Cleaning up Sandboxie environment...")
            self.full_cleanup_sandbox()
            self.full_cleanup_sandbox()

            # Step 3: Clean up directories
            self.output_signal.emit("[*] Step 3: Cleaning up generated directories...")
            self.cleanup_directories()
            self.cleanup_directories()

            # Step 4: Stop and cleanup logging files
            self.output_signal.emit("[*] Step 4: Stopping logging and cleaning log files...")
            self.cleanup_logging_files()
            self.reinitialize_logging()

            # Step 5: Reset global variables
            self.output_signal.emit("[*] Step 5: Resetting analysis state...")
            pre_analysis_log_path = None
            post_analysis_log_path = None
            pre_analysis_entries = None
            post_analysis_entries = None
            reset_flags()
            clear_pe_cache()

            # Step 6: Restart services
            self.output_signal.emit("[*] Step 6: Restarting services...")
            self.restart_services()

            # Step 7: Remove Owlyshield av events json file
            remove_log_file(av_events_json_file_path)

            # Step 8: Recreate directories
            self.output_signal.emit("[*] Step 8: Recreating clean directories...")
            self.recreate_directories()

            self.output_signal.emit("[+] Environment cleanup completed successfully!")
            self.output_signal.emit("[+] System is ready for new analysis.")

        except Exception as e:
            self.output_signal.emit(f"[!] Error during cleanup: {str(e)}")

    def update_hayabusa_rules(self):
        """
        Updates Hayabusa rules to the latest version from the GitHub repository.
        """
        try:
            self.output_signal.emit("[*] Updating Hayabusa rules...")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Run the update-rules command
            cmd = [hayabusa_path, "update-rules"]
            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            # Use Popen with terminal popup for real-time output
            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path)
            )

            # Wait for process to complete and get return code
            rc = process.wait()

            if rc == 0:
                self.output_signal.emit("[+] Hayabusa rules updated successfully!")
            else:
                self.output_signal.emit(f"[!] Failed to update Hayabusa rules. Return code: {rc}")

        except Exception as e:
            self.output_signal.emit(f"[!] Error updating Hayabusa rules: {str(e)}")

    def run_hayabusa_timeline(self, output_format="csv"):
        """
        Creates a DFIR timeline using Hayabusa for event log analysis.
        """
        try:
            self.output_signal.emit("[*] Starting Hayabusa timeline analysis...")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_analysis_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)

            # Set output file based on format
            if output_format.lower() == "json":
                output_file = os.path.join(output_dir, f"hayabusa_timeline_{timestamp}.jsonl")
                cmd = [hayabusa_path, "json-timeline", "-d", evtx_logs_path, "-o", output_file]
            else:
                output_file = os.path.join(output_dir, f"hayabusa_timeline_{timestamp}.csv")
                cmd = [hayabusa_path, "csv-timeline", "-d", evtx_logs_path, "-o", output_file]

            # Add profile but keep colors and progress
            cmd.extend(["--profile", "standard"])

            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            # Use Popen with terminal popup for real-time output
            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path)
            )

            # Wait for process to complete and get return code
            rc = process.wait()

            if rc == 0:
                self.output_signal.emit("[+] Hayabusa timeline analysis completed successfully!")
                self.output_signal.emit(f"[+] Output saved to: {output_file}")

                # Show basic statistics if available
                if os.path.exists(output_file):
                    file_size = os.path.getsize(output_file)
                    self.output_signal.emit(f"[+] Timeline file size: {file_size:,} bytes")

                    # Count lines for CSV or events for JSON
                    try:
                        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                            line_count = sum(1 for _ in f)
                            if output_format.lower() == "json":
                                self.output_signal.emit(f"[+] Total events analyzed: {line_count:,}")
                            else:
                                self.output_signal.emit(f"[+] Total events in timeline: {line_count - 1:,}")
                    except Exception as e:
                        self.output_signal.emit(f"[!] Could not count events: {str(e)}")
            else:
                self.output_signal.emit(f"[!] Hayabusa timeline analysis failed. Return code: {rc}")
        except Exception as e:
            self.output_signal.emit(f"[!] Error running Hayabusa timeline: {str(e)}")

    def run_hayabusa_search(self, keywords, regex=False):
        """
        Search Windows event logs using Hayabusa for specific keywords or patterns.
        """
        try:
            self.output_signal.emit(f"[*] Searching event logs with Hayabusa for: {keywords}")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_search_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"hayabusa_search_{timestamp}.csv")

            # Build search command
            cmd = [hayabusa_path, "search", "-d", evtx_logs_path, "-o", output_file]

            # Add keywords or regex
            if regex:
                cmd.extend(["-r", keywords])
            else:
                cmd.extend(["-k", keywords])

            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            # Use Popen with terminal popup for real-time output
            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path)
            )

            # Wait for process to complete and get return code
            rc = process.wait()

            if rc == 0:
                self.output_signal.emit("[+] Hayabusa search completed successfully!")
                self.output_signal.emit(f"[+] Results saved to: {output_file}")

                # Show search results summary
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = f.readlines()
                            if len(lines) > 1:  # More than just header
                                result_count = len(lines) - 1
                                self.output_signal.emit(f"[+] Found {result_count} matching events")
                                self.output_signal.emit("[*] Sample results:")
                                for i, line in enumerate(lines[:6]):  # Header + 5 results
                                    self.output_signal.emit(f"  {line.strip()}")
                                    if i == 5:
                                        self.output_signal.emit("  ...")
                                        break
                            else:
                                self.output_signal.emit("[*] No matching events found")
                    except Exception as e:
                        self.output_signal.emit(f"[!] Could not read results: {str(e)}")
            else:
                self.output_signal.emit(f"[!] Hayabusa search failed. Return code: {rc}")
        except Exception as e:
            self.output_signal.emit(f"[!] Error running Hayabusa search: {str(e)}")

    def run_hayabusa_logon_summary(self):
        """
        Generate a logon summary report using Hayabusa.
        """
        try:
            self.output_signal.emit("[*] Generating logon summary with Hayabusa...")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_logon_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)
            output_file = os.path.join(output_dir, f"logon_summary_{timestamp}.csv")

            cmd = [hayabusa_path, "logon-summary", "-d", evtx_logs_path, "-o", output_file]

            self.output_signal.emit(f"[*] Running command: {' '.join(cmd)}")

            # Use Popen with terminal popup for real-time output
            process = subprocess.Popen(
                cmd,
                cwd=os.path.dirname(hayabusa_path)
            )

            # Wait for process to complete and get return code
            rc = process.wait()

            if rc == 0:
                self.output_signal.emit("[+] Hayabusa logon summary completed successfully!")
                self.output_signal.emit(f"[+] Results saved to: {output_file}")

                # Show logon summary
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            if content.strip():
                                self.output_signal.emit("[*] Logon Summary:")
                                self.output_signal.emit(content)
                            else:
                                self.output_signal.emit("[*] No logon data found")
                    except Exception as e:
                        self.output_signal.emit(f"[!] Could not read logon summary: {str(e)}")
            else:
                self.output_signal.emit(f"[!] Hayabusa logon summary failed. Return code: {rc}")
        except Exception as e:
            self.output_signal.emit(f"[!] Error running Hayabusa logon summary: {str(e)}")

    def run_hayabusa_metrics(self):
        """
        Generate various metrics using Hayabusa (log metrics, EID metrics, etc.).
        """
        try:
            self.output_signal.emit("[*] Generating system metrics with Hayabusa...")

            # Check if Hayabusa executable exists
            if not os.path.exists(hayabusa_path):
                self.output_signal.emit(f"[!] Hayabusa executable not found at: {hayabusa_path}")
                return

            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = os.path.join(log_directory, f"hayabusa_metrics_{timestamp}")
            os.makedirs(output_dir, exist_ok=True)

            # Run different metrics commands
            metrics_commands = [
                ("log-metrics", "log_metrics.csv"),
                ("eid-metrics", "eid_metrics.csv"),
                ("computer-metrics", "computer_metrics.csv")
            ]

            for metric_type, output_filename in metrics_commands:
                output_file = os.path.join(output_dir, output_filename)
                cmd = [hayabusa_path, metric_type, "-d", evtx_logs_path, "-o", output_file]

                self.output_signal.emit(f"[*] Running {metric_type} analysis...")
                self.output_signal.emit(f"[*] Command: {' '.join(cmd)}")

                # Use Popen with terminal popup for real-time output
                process = subprocess.Popen(
                    cmd,
                    cwd=os.path.dirname(hayabusa_path)
                )

                # Wait for process to complete and get return code
                rc = process.wait()

                if rc == 0:
                    self.output_signal.emit(f"[+] {metric_type} completed successfully!")
                    self.output_signal.emit(f"[+] Results saved to: {output_file}")

                    # Show brief summary of results
                    if os.path.exists(output_file):
                        try:
                            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                                lines = f.readlines()
                                if len(lines) > 1:
                                    self.output_signal.emit(f"[+] Generated {len(lines) - 1} {metric_type} entries")
                                else:
                                    self.output_signal.emit(f"[*] No {metric_type} data found")
                        except Exception as e:
                            self.output_signal.emit(f"[!] Could not read {metric_type} results: {str(e)}")
                else:
                    self.output_signal.emit(f"[!] {metric_type} failed. Return code: {rc}")
        except Exception as e:
            self.output_signal.emit(f"[!] Error running Hayabusa metrics: {str(e)}")

    def run(self):
        """The entry point for the thread."""
        try:
            task_mapping = {
                "capture_analysis_logs": self.capture_analysis_logs,
                "compare_analysis_logs": self.compare_analysis_logs,
                "update_defs": self.update_definitions,
                "generate_whitelist_db": self.generate_whitelist_db,
                "rootkit_scan": self.perform_rootkit_scan,
                "cleanup_environment": self.perform_cleanup,
                "load_meta_llama_1b_model": self.load_meta_llama_1b_model,
                "update_hayabusa_rules": self.update_hayabusa_rules,
                "hayabusa_timeline_csv": lambda: self.run_hayabusa_timeline("csv"),
                "hayabusa_timeline_json": lambda: self.run_hayabusa_timeline("json"),
                "hayabusa_logon_summary": self.run_hayabusa_logon_summary,
                "hayabusa_metrics": self.run_hayabusa_metrics,
                "analyze_file": lambda: self.analyze_file_worker(*self.args),
                "hayabusa_search": lambda: self.run_hayabusa_search(*self.args)
            }

            task_function = task_mapping.get(self.task_type)
            if task_function:
                task_function()
            else:
                self.output_signal.emit(f"[!] Unknown task type: {self.task_type}")
        except Exception as e:
            if not self.stop_requested:
                self.output_signal.emit(f"[!] Worker thread error: {str(e)}")

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

            #action_button_danger {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #BF616A, stop:1 #B34C56);
                color: #ECEFF4;
                border-radius: 10px;
                padding: 14px 24px;
                font-size: 14px;
                font-weight: bold;
                border: none;
            }

            #action_button_danger:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #D08770, stop:1 #C47766);
            }

            QGroupBox {
                font-weight: bold;
                border: 2px solid #4C566A;
                border-radius: 12px;
                margin-top: 15px;
                padding: 20px;
                background-color: #3B4252;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                background-color: #5E81AC;
                color: #ECEFF4;
                border-radius: 6px;
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
                    self.status_text.setText("Ready for analysis!")

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

    def stop_analysis(self):
        if not self.workers:
            self.append_log_output("[!] No running tasks to stop.")
            return
        self.append_log_output("[*] Requesting stop for all running tasks...")
        for worker in self.workers[:]:
            if worker.isRunning():
                worker.request_stop()
                self.append_log_output(f"[*] Stop requested for task: {worker.task_type}")
        threading.Timer(1.0, self.force_stop_remaining_workers).start()

    def force_stop_remaining_workers(self):
        remaining_workers = [w for w in self.workers if w.isRunning()]
        if remaining_workers:
            self.append_log_output(f"[*] Force stopping {len(remaining_workers)} remaining tasks...")
            for worker in remaining_workers:
                try:
                    worker.terminate()
                    worker.wait(2000)
                    if worker.isRunning():
                        self.append_log_output(f"[!] Could not stop task: {worker.task_type}")
                    else:
                        self.append_log_output(f"[+] Force stopped task: {worker.task_type}")
                except Exception as e:
                    self.append_log_output(f"[!] Error stopping task {worker.task_type}: {str(e)}")
        self.workers.clear()
        if hasattr(self, 'shield_widget'):
            self.shield_widget.set_status(True)
        if hasattr(self, 'status_text'):
            self.status_text.setText("Ready for analysis!")

    def open_sandboxie_control(self):
        self.append_log_output("[*] Opening Sandboxie Control window...")
        def run_thread():
            try:
                run_sandboxie_control()
                self.append_log_output("[+] Sandboxie Control window opened successfully.")
            except Exception as e:
                self.append_log_output(f"[!] Error opening Sandboxie Control: {str(e)}")
        thread = threading.Thread(target=run_thread)
        thread.start()

    def analyze_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to analyze", "", "All Files (*)")
        if file_path:
            self.append_log_output(f"[*] Selected file for analysis: {file_path}")
            self.start_worker("analyze_file", file_path)
        else:
            self.append_log_output("[*] File selection cancelled.")

    def perform_hayabusa_search(self):
        if not hasattr(self, 'search_input'):
            self.append_log_output("[!] Search input not available.")
            return
        keywords = self.search_input.text().strip()
        if keywords:
            self.start_worker("hayabusa_search", keywords, False)
        else:
            self.append_log_output("[!] Please enter search keywords first.")

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
        if self.workers:
            self.append_log_output("[*] Stopping all running tasks before exit...")
            for worker in self.workers:
                if worker.isRunning():
                    worker.request_stop()
            for worker in self.workers:
                if worker.isRunning():
                    worker.terminate()
                    worker.wait(3000)
        event.accept()

    def create_status_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(30)

        # Status cards row
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(20)

        # Enable GUI mode for alert tracking
        setup_gui_mode(self)

        # Create status cards first
        self.threat_card = StatusCard("Critical Threats", "0", "⚠️")
        self.scan_card = StatusCard("Events", "0", "🧾")
        self.uptime_card = StatusCard("System Uptime", "Ready", "⏱️")

        # Now update status cards with current counts
        critical_count, event_count = get_alert_counts()
        self.threat_card.value_label.setText(str(critical_count))
        self.scan_card.value_label.setText(str(event_count))
        self.uptime_card.value_label.setText("Ready")  # could later be replaced with real uptime

        # Add the whole card widgets to the layout
        cards_layout.addWidget(self.threat_card)
        cards_layout.addWidget(self.scan_card)
        cards_layout.addWidget(self.uptime_card)

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
        self.status_text = QLabel("Ready for analysis!")
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

    def create_task_page(self, title_text, task_name):
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
        button = QPushButton(f"Run {title_text}")
        button.setObjectName("action_button")
        button.clicked.connect(lambda: self.start_worker(task_name))
        button_container.addWidget(button)
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

    def create_analysis_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("Deep File Analysis")
        title.setObjectName("page_title")
        layout.addWidget(title)

        warning_box = QGroupBox("Recommended Workflow")
        warning_layout = QVBoxLayout(warning_box)
        warning_text = QLabel(
            "<b>IMPORTANT:</b> Only run this application from a Virtual Machine.<br><br>"
            "<b>NOTICE:</b> HydraDragonDumper x64 must be used to create clean hashes before you download malware.<br><br>"
            "<b>Recommended Workflow:</b><br>"
            "1. Update ClamAV and Hayabusa Virus Definitions<br>"
            "2. Generate Clean DB with HydraDragonDumper x64 (Highly Recommended) <br>"
            "3. Capture Pre-analysis Logs<br>"
            "4. Analyze a File<br>"
            "5. Stop Analysis<br>"
            "6. Capture Post-analysis Logs and Compare Results (with Llama AI)<br>"
            "7. Rootkit Scan<br>"
            "8. Hayabusa SIGMA SIEM CSV-timeline Scan<br>"
            "9. Cleanup Environment<br><br>"
            "<i>Return to a clean snapshot before starting a new analysis.</i>"
        )
        warning_text.setWordWrap(True)
        warning_text.setObjectName("warning_text")
        warning_layout.addWidget(warning_text)
        layout.addWidget(warning_box)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(15)

        analyze_btn = QPushButton("Analyze File...")
        analyze_btn.setObjectName("action_button")
        analyze_btn.clicked.connect(self.analyze_file)

        stop_btn = QPushButton("Stop Analysis")
        stop_btn.setObjectName("action_button_danger")
        stop_btn.clicked.connect(self.stop_analysis)

        button_layout.addWidget(analyze_btn)
        button_layout.addWidget(stop_btn)
        button_layout.addStretch()
        layout.addLayout(button_layout)

        control_layout = QHBoxLayout()
        sandboxie_control_btn = QPushButton("Open Sandboxie Control")
        sandboxie_control_btn.setObjectName("action_button")
        sandboxie_control_btn.clicked.connect(self.open_sandboxie_control)
        control_layout.addWidget(sandboxie_control_btn)
        control_layout.addStretch()
        layout.addLayout(control_layout)

        log_output = QTextEdit("Analysis logs will be saved in the logs folder.")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)

        self.log_outputs.append(log_output)
        return page

    def create_hayabusa_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("Hayabusa Event Log Analysis")
        title.setObjectName("page_title")
        layout.addWidget(title)

        info_box = QGroupBox("About Hayabusa")
        info_layout = QVBoxLayout(info_box)
        info_text = QLabel(
            "Hayabusa is a Windows event log fast forensics timeline generator and threat hunting tool. "
            "It can create DFIR timelines, search for specific events, and generate various security metrics."
        )
        info_text.setWordWrap(True)
        info_text.setObjectName("warning_text")
        info_layout.addWidget(info_text)
        layout.addWidget(info_box)

        update_rules_btn = QPushButton("Update Hayabusa Rules Database")
        update_rules_btn.setObjectName("action_button")
        update_rules_btn.clicked.connect(lambda: self.start_worker("update_hayabusa_rules"))
        layout.addWidget(update_rules_btn)

        timeline_layout = QHBoxLayout()
        timeline_layout.setSpacing(15)

        csv_timeline_btn = QPushButton("Generate CSV Timeline")
        csv_timeline_btn.setObjectName("action_button")
        csv_timeline_btn.clicked.connect(lambda: self.start_worker("hayabusa_timeline_csv"))

        json_timeline_btn = QPushButton("Generate JSON Timeline")
        json_timeline_btn.setObjectName("action_button")
        json_timeline_btn.clicked.connect(lambda: self.start_worker("hayabusa_timeline_json"))

        timeline_layout.addWidget(csv_timeline_btn)
        timeline_layout.addWidget(json_timeline_btn)
        timeline_layout.addStretch()
        layout.addLayout(timeline_layout)

        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter keywords to search in event logs...")
        self.search_input.setMinimumHeight(42)

        search_btn = QPushButton("Search Events")
        search_btn.setObjectName("action_button")
        search_btn.clicked.connect(self.perform_hayabusa_search)

        search_layout.addWidget(self.search_input, 1)
        search_layout.addWidget(search_btn)
        layout.addLayout(search_layout)

        analysis_layout = QHBoxLayout()
        analysis_layout.setSpacing(15)

        logon_summary_btn = QPushButton("Logon Summary")
        logon_summary_btn.setObjectName("action_button")
        logon_summary_btn.clicked.connect(lambda: self.start_worker("hayabusa_logon_summary"))

        metrics_btn = QPushButton("System Metrics")
        metrics_btn.setObjectName("action_button")
        metrics_btn.clicked.connect(lambda: self.start_worker("hayabusa_metrics"))

        analysis_layout.addWidget(logon_summary_btn)
        analysis_layout.addWidget(metrics_btn)
        analysis_layout.addStretch()
        layout.addLayout(analysis_layout)

        log_output = QTextEdit("Hayabusa analysis results will appear here...")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)

        self.log_outputs.append(log_output)
        return page

    def create_generate_whitelist_db_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("Generate Whitelist DB")
        title.setObjectName("page_title")
        layout.addWidget(title)

        generate_button = QPushButton("Run Generate Whitelist DB (Highly Recommended)")
        generate_button.setObjectName("action_button")
        generate_button.clicked.connect(lambda: self.start_worker("generate_whitelist_db"))
        layout.addWidget(generate_button)

        log_output = QTextEdit("Generate Whitelist DB logs will appear here...")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)

        self.log_outputs.append(log_output)
        return page

    def create_cleanup_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        title = QLabel("System Cleanup & Reset")
        title.setObjectName("page_title")
        layout.addWidget(title)

        cleanup_button = QPushButton("Perform Full Environment Cleanup")
        cleanup_button.setObjectName("action_button_danger")
        cleanup_button.clicked.connect(lambda: self.start_worker("cleanup_environment"))
        layout.addWidget(cleanup_button)

        log_output = QTextEdit("Cleanup process logs will appear here...")
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
            "HydraDragon Antivirus is a tool designed for malware analysis and system security research. "
            "It provides a sandboxed environment to safely analyze potential threats."
        )
        about_text.setWordWrap(True)
        layout.addWidget(about_text)

        buttons_layout = QVBoxLayout()
        buttons_layout.setSpacing(15)

        llama_load_button = QPushButton("Load Meta Llama AI Model (Requires >8GB RAM)")
        llama_load_button.setObjectName("action_button")
        llama_load_button.clicked.connect(lambda: self.start_worker("load_meta_llama_1b_model"))
        buttons_layout.addWidget(llama_load_button, 0, Qt.AlignmentFlag.AlignLeft)

        github_button = QPushButton("View Project on GitHub")
        github_button.setObjectName("action_button")
        github_button.clicked.connect(lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus"))
        buttons_layout.addWidget(github_button, 0, Qt.AlignmentFlag.AlignLeft)

        llama_release_button = QPushButton("View Meta Llama Release")
        llama_release_button.setObjectName("action_button")
        llama_release_button.clicked.connect(lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus/releases/tag/MetaLlama"))
        buttons_layout.addWidget(llama_release_button, 0, Qt.AlignmentFlag.AlignLeft)

        layout.addLayout(buttons_layout)

        log_output = QTextEdit("Llama AI model status will appear here...")
        log_output.setObjectName("log_output")
        log_output.setReadOnly(True)
        layout.addWidget(log_output, 1)

        self.log_outputs.append(log_output)
        return page

    def create_main_content(self):
        self.main_stack = QStackedWidget()
        self.main_stack.addWidget(self.create_status_page())
        self.main_stack.addWidget(self.create_task_page("Update ClamAV Definitions", "update_defs"))
        self.main_stack.addWidget(self.create_generate_whitelist_db_page())
        self.main_stack.addWidget(self.create_analysis_page())
        self.main_stack.addWidget(self.create_task_page("Capture Analysis Logs", "capture_analysis_logs"))
        self.main_stack.addWidget(self.create_task_page("Compare Logs (Llama AI)", "compare_analysis_logs"))
        self.main_stack.addWidget(self.create_task_page("Rootkit Scan", "rootkit_scan"))
        self.main_stack.addWidget(self.create_hayabusa_page())
        self.main_stack.addWidget(self.create_cleanup_page())
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
            ("🔄", "Update ClamAV"),
            ("🗃️", "Generate Clean DB"),
            ("🔍", "Analyze File"),
            ("📋", "Capture Logs"),
            ("🤖", "Compare Logs"),
            ("🛡️", "Rootkit Scan"),
            ("📊", "Hayabusa Analysis"),
            ("🧹", "Cleanup"),
            ("ℹ️", "About & AI")
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
    window = AntivirusApp()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
