#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import asyncio
import traceback
import webbrowser
import subprocess
import threading
import tkinter
import queue
from datetime import datetime, timedelta

# --- New Imports for CustomTkinter ---
import customtkinter
from PIL import Image, ImageTk

# Ensure the script's directory is the working directory
main_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(main_dir)

# Add the main directory to sys.path to allow absolute imports
if main_dir not in sys.path:
    sys.path.insert(0, main_dir)

from hydradragon.antivirus_scripts.antivirus import logger

# --- Import necessary functions from antivirus script ---
from hydradragon.antivirus_scripts.antivirus import (
    start_real_time_protection_async,  # Async function (not generator)
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
    icon_animated_protected_path,
    icon_animated_unprotected_path
)

# --- CTk Styling Constants (from original stylesheet) ---
COLOR_BG = "#2E3440"
COLOR_BG_LIGHT = "#3B4252"
COLOR_BG_DARK = "#232831"
COLOR_BORDER = "#4C566A"
COLOR_TEXT = "#D8DEE9"
COLOR_TEXT_EMPHASIS = "#ECEFF4"
COLOR_ACCENT = "#88C0D0"
COLOR_ACCENT_ALT = "#81A1C1"
COLOR_ACTION = "#5E81AC"
COLOR_ACTION_HOVER = "#81A1C1"
COLOR_SUCCESS = (163, 190, 140) # RGB for interpolation/glow
COLOR_WARNING = (235, 203, 139) # RGB for interpolation/glow
COLOR_SHIELD_BG = "#3B4252"
COLOR_BG_RGB = (46, 52, 64) # RGB for interpolation

# Set CTk appearance
customtkinter.set_appearance_mode("Dark")
customtkinter.set_default_color_theme("blue")

# --- Helper to convert RGB to Hex ---
def _rgb_to_hex(rgb):
    """Convert an RGB tuple to a hex string."""
    return f"#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}"


# --- Animated Shield Widget ---
class AnimatedShieldWidget(customtkinter.CTkFrame):
    def __init__(self, parent, size=250):
        super().__init__(parent)
        self.queue = queue.Queue()
        threading.Thread(target=self._load_gifs_async, daemon=True).start()
        self.after(50, self._process_queue)

    def _load_gifs_async(self):
        try:
            protected_frames, protected_delay = self.load_gif_frames(icon_animated_protected_path)
            unprotected_frames, unprotected_delay = self.load_gif_frames(icon_animated_unprotected_path)
        except Exception:
            logger.exception("GIF load failed")  # proper exception logging
            protected_frames, protected_delay = [], 100
            unprotected_frames, unprotected_delay = [], 100

        self.after(0, self._set_loaded_frames, protected_frames, protected_delay,
                unprotected_frames, unprotected_delay)

    def _process_queue(self):
        """Poll queue from main thread."""
        try:
            while not self.queue.empty():
                protected_pil, protected_delay, unprotected_pil, unprotected_delay = self.queue.get_nowait()
                
                self.protected_frames = [customtkinter.CTkImage(light_image=f, size=(self.size, self.size)) for f in protected_pil] or self.create_fallback_image(_rgb_to_hex(COLOR_SUCCESS))
                self.protected_delay = protected_delay
                self.unprotected_frames = [customtkinter.CTkImage(light_image=f, size=(self.size, self.size)) for f in unprotected_pil] or self.create_fallback_image(_rgb_to_hex(COLOR_WARNING))
                self.unprotected_delay = unprotected_delay

                self.set_status(True)
        except queue.Empty:
            pass
        self.after(50, self._process_queue)

class AntivirusApp(customtkinter.CTk):

    def __init__(self):
        super().__init__(fg_color=COLOR_BG)
        
        # state
        self.active_tasks = set()
        self.log_outputs = []  # list of CTkTextbox widgets for each page
        self.task_buttons = {}
        self.nav_buttons = []
        self.pages = []
        self.is_running = True # Flag for the async mainloop
        self.loop_time = 0.0 # Time for animations
        self.current_page_index = 0
        self.is_page_animating = False

        # --- Configure main window ---
        self.title(WINDOW_TITLE)
        self.geometry("1400x900")
        self.minsize(550, 400)
        
        # Set window icon
        if os.path.exists(icon_path):
            try:
                if sys.platform == "win32" and icon_path.endswith(".png"):
                    pil_icon = Image.open(icon_path)
                    self.iconphoto(True, ImageTk.PhotoImage(pil_icon))
                elif os.path.exists(icon_path.replace(".png", ".ico")):
                     self.iconbitmap(icon_path.replace(".png", ".ico"))
                else:
                    logger.warning(f"Could not set window icon from {icon_path}. Platform: {sys.platform}")
            except Exception as e:
                logger.error(f"Error setting window icon: {e}")

        # Configure root grid
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1) # Main content column expands

        # Build UI
        self.create_sidebar()
        self.create_main_content()
        
        # Select first page (no animation)
        self._make_nav_handler(0)(animate=False)
        
        # Set initial status
        self.after(100, lambda: self.set_status(True))
        
        # Handle window close
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ---------------------------
    # Async main loop driver
    # ---------------------------
    async def mainloop_async(self):
        """Drives both the asyncio event loop and the Tkinter UI."""
        self.loop_time = asyncio.get_event_loop().time()
        while self.is_running:
            try:
                # Update loop time for animations
                self.loop_time = asyncio.get_event_loop().time()
                
                # Update Tkinter UI
                self.update_idletasks()
                self.update()
            except tkinter.TclError as e:
                logger.warning(f"Tkinter error in mainloop: {e}. Stopping loop.")
                self.is_running = False
            
            # Yield control to asyncio
            await asyncio.sleep(0.01) # ~60 FPS update rate

    def on_closing(self):
        """Handle the window close event."""
        self.append_log_output("[*] Closing application...")
        self.is_running = False
        
        # Stop animations in shield widget
        if hasattr(self, 'shield_widget') and self.shield_widget:
            self.shield_widget.stop_animation()
            
        self.after(50, self.destroy)


    # ---------------------------
    # Signal/Slot replacements (now using self.after)
    # ---------------------------
    def _append_log_output_slot(self, text: str):
        """Append log messages to the current log widget (runs on Tk thread)."""
        try:
            if 0 <= self.current_page_index < len(self.log_outputs):
                log_widget = self.log_outputs[self.current_page_index]
                if log_widget and isinstance(log_widget, customtkinter.CTkTextbox):
                    log_widget.configure(state="normal")
                    log_widget.insert("end", f"{text}\n")
                    log_widget.see("end") # Autoscroll
                    log_widget.configure(state="disabled")
        except Exception:
            logger.exception("Error in _append_log_output_slot")


    def set_status(self, is_protected: bool):
        """Slot to update shield & status text; always runs on the Tk thread."""
        try:
            if hasattr(self, 'shield_widget') and self.shield_widget:
                # This now calls the AnimatedShieldWidget's set_status
                self.shield_widget.set_status(bool(is_protected))
            if hasattr(self, 'status_text') and self.status_text:
                text = "System protected!" if is_protected else "System unprotected!..."
                color = _rgb_to_hex(COLOR_SUCCESS) if is_protected else _rgb_to_hex(COLOR_WARNING)
                self.status_text.configure(text=text, text_color=color)
        except Exception:
            logger.exception("Error in set_status")


    def _on_progress_signal(self, value: float):
        """Receive progress updates (0.0..1.0) and update progress bar."""
        try:
            if hasattr(self, 'defs_progress_bar') and isinstance(self.defs_progress_bar, customtkinter.CTkProgressBar):
                self.defs_progress_bar.set(float(value))
        except Exception:
            logger.exception("Error in _on_progress_signal")


    # ---------------------------
    # Logging wrapper
    # ---------------------------
    def append_log_output(self, text: str):
        """Thread-safe/log-safe way to append logs to UI via self.after."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            formatted = f"{timestamp} {text}"
            # self.after schedules the callback on the main Tkinter thread
            self.after(0, self._append_log_output_slot, formatted)
            logger.info(text)
        except Exception:
            logger.exception("append_log_output failed")

    # ---------------------------
    # Task runner utilities - MODIFIED to remove yield handling
    # ---------------------------
    def _update_ui_for_task_start(self, task_name: str):
        """Update UI when a task starts (runs on Tk thread)."""
        try:
            self.append_log_output(f"[*] Task '{task_name}' started.")
            self.set_status(False)
            if hasattr(self, 'task_buttons') and task_name in self.task_buttons:
                self.task_buttons[task_name].configure(state="disabled")
        except Exception:
            logger.exception("_update_ui_for_task_start failed")


    def _update_ui_for_task_end(self, task_name: str):
        """Update UI when a task ends (runs on Tk thread)."""
        try:
            self.append_log_output(f"[+] Task '{task_name}' finished.")
            if not self.active_tasks:
                self.set_status(True)

            if hasattr(self, 'task_buttons') and task_name in self.task_buttons:
                self.task_buttons[task_name].configure(state="normal")

            if task_name == 'update_definitions' and self.defs_label:
                self.defs_label.configure(text=get_latest_clamav_def_time())
        except Exception:
            logger.exception("_update_ui_for_task_end failed")


    async def run_task(self, task_name: str, coro_or_func, *args, is_async: bool = True):
        """
        Run an async coroutine or blocking function.
        REMOVED: async generator handling (no more yield support).
        Handles UI updates safely via self.after().
        """
        if task_name in self.active_tasks:
            self.append_log_output(f"[*] Task '{task_name}' already running.")
            return

        self.active_tasks.add(task_name)
        self.after(0, self._update_ui_for_task_start, task_name)

        try:
            if is_async:
                # Simply await the coroutine (no generator support)
                msg = await coro_or_func(*args)
                if msg:
                    self.append_log_output(str(msg))
            else:
                # Run blocking function in a separate thread
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
            self.after(0, self._update_ui_for_task_end, task_name)

    # ---------------------------
    # Sync (blocking) tasks
    # ---------------------------
    
    def _update_definitions_sync(self):
        self._update_definitions_clamav_sync()
        self.after(0, self._on_progress_signal, 0.5) # Update progress bar
        self._update_definitions_hayabusa_sync()
        self.after(0, self._on_progress_signal, 1.0)

    def _update_definitions_clamav_sync(self):
        self.append_log_output("[*] Checking virus definitions (ClamAV)...")
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
                proc = subprocess.Popen(
                    [freshclam_path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True, encoding="utf-8", errors="ignore"
                )
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
                self.append_log_output("[*] ClamAV definitions are already up to date.")
                return True
        except Exception:
            self.append_log_output(f"[!] ClamAV update error: {traceback.format_exc()}")
            logger.exception("ClamAV update failed")
            return False

    def _update_definitions_hayabusa_sync(self):
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
            if stdout:
                for line in stdout.splitlines():
                    self.append_log_output(f"[Hayabusa Update] {line}")
            if stderr:
                for line in stderr.splitlines():
                    self.append_log_output(f"[Hayabusa Update ERR] {line}")
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
    # Button handlers
    # ---------------------------
    def on_update_definitions_clicked(self):
        # Reset progress bar
        self.after(0, self._on_progress_signal, 0.0)
        # Run the task
        asyncio.create_task(
            self.run_task('update_definitions', self._update_definitions_sync, is_async=False)
        )

    # ---------------------------
    # UI Pages / layout creation (Using .place() for animations)
    # ---------------------------
    def create_status_page(self, parent):
        page = customtkinter.CTkFrame(parent, fg_color="transparent")
        
        # Shield Widget Area
        shield_frame = customtkinter.CTkFrame(page, fg_color="transparent")
        shield_frame.place(relx=0, rely=0.5, relwidth=0.4, relheight=1.0, anchor="w")
        
        # --- Use AnimatedShieldWidget ---
        self.shield_widget = AnimatedShieldWidget(shield_frame, size=250)
        self.shield_widget.pack(expand=True, anchor="center", padx=40, pady=40)

        # Status Text Area
        status_vbox = customtkinter.CTkFrame(page, fg_color="transparent")
        status_vbox.place(relx=0.45, rely=0.5, relwidth=0.55, relheight=1.0, anchor="w")
        
        title = customtkinter.CTkLabel(
            status_vbox,
            text="System Status",
            font=("Segoe UI", 32, "normal"),
            text_color=COLOR_TEXT_EMPHASIS
        )
        title.pack(anchor="w", pady=(0, 20))

        self.status_text = customtkinter.CTkLabel(
            status_vbox,
            text="Initializing...",
            font=("Segoe UI", 18, "bold"),
            text_color=_rgb_to_hex(COLOR_WARNING)
        )
        self.status_text.pack(anchor="w")

        customtkinter.CTkFrame(status_vbox, height=30, fg_color="transparent").pack()

        version_label = customtkinter.CTkLabel(
            status_vbox,
            text=WINDOW_TITLE,
            font=("Segoe UI", 13),
            text_color=COLOR_ACCENT_ALT
        )
        version_label.pack(anchor="w")

        self.defs_label = customtkinter.CTkLabel(
            status_vbox,
            text=get_latest_clamav_def_time(),
            font=("Segoe UI", 13),
            text_color=COLOR_ACCENT_ALT
        )
        self.defs_label.pack(anchor="w")
        
        self.log_outputs.append(None)
        return page

    def create_task_page(self, parent, title_text, main_task_name, main_button_text, on_click_handler=None):
        page = customtkinter.CTkFrame(parent, fg_color="transparent")
        
        title = customtkinter.CTkLabel(
            page,
            text=title_text,
            font=("Segoe UI", 32, "normal"),
            text_color=COLOR_TEXT_EMPHASIS
        )
        title.place(relx=0, rely=0, x=30, y=30)

        button_container = customtkinter.CTkFrame(page, fg_color="transparent")
        button_container.place(relx=0, rely=0, x=30, y=90, relwidth=1)
        
        main_button = customtkinter.CTkButton(
            button_container,
            text=main_button_text,
            font=("Segoe UI", 14, "bold"),
            fg_color=COLOR_ACTION,
            hover_color=COLOR_ACTION_HOVER,
            text_color=COLOR_TEXT_EMPHASIS,
            corner_radius=10,
            height=40,
        )
        main_button.pack(side="left", padx=(0, 15))
        
        self.task_buttons[main_task_name] = main_button

        # Set up command handler
        if on_click_handler:
            main_button.configure(command=on_click_handler)
        elif main_task_name == 'update_definitions':
            main_button.configure(command=self.on_update_definitions_clicked)
            
            # Progress bar for updates
            self.defs_progress_bar = customtkinter.CTkProgressBar(
                button_container,
                orientation="horizontal",
                progress_color=COLOR_ACCENT,
                fg_color=COLOR_BG_LIGHT,
                border_color=COLOR_BORDER,
                border_width=2
            )
            self.defs_progress_bar.pack(side="left", fill="x", expand=True, padx=20, pady=5)
            self.defs_progress_bar.set(0)
        else:
            # If no handler provided, keep button enabled but show a message
            main_button.configure(
                command=lambda: self.append_log_output(f"[*] {main_button_text} feature coming soon!")
            )

        # Log Output
        log_output = customtkinter.CTkTextbox(
            page,
            font=("JetBrains Mono", 13),
            border_width=2,
            border_color=COLOR_BORDER,
            fg_color=COLOR_BG_LIGHT,
            text_color=COLOR_TEXT_EMPHASIS,
            corner_radius=10,
        )
        log_output.place(relx=0, rely=0, x=30, y=150, relwidth=1, relheight=1)
        log_output.insert("1.0", f"{title_text} logs will appear here...")
        log_output.configure(state="disabled") # Make read-only

        self.log_outputs.append(log_output)
        return page

    def create_about_page(self, parent):
        page = customtkinter.CTkFrame(parent, fg_color="transparent")

        title = customtkinter.CTkLabel(
            page,
            text="About HydraDragon",
            font=("Segoe UI", 32, "normal"),
            text_color=COLOR_TEXT_EMPHASIS
        )
        title.place(relx=0, rely=0, x=40, y=40)
        
        about_text = customtkinter.CTkLabel(
            page,
            text="HydraDragon Antivirus - Open Source Antivirus with Advanced Real-Time Protection.",
            font=("Segoe UI", 15),
            wraplength=800,
            justify="left"
        )
        about_text.place(relx=0, rely=0, x=40, y=110)

        github_button = customtkinter.CTkButton(
            page,
            text="View on GitHub",
            font=("Segoe UI", 14, "bold"),
            fg_color=COLOR_ACTION,
            hover_color=COLOR_ACTION_HOVER,
            text_color=COLOR_TEXT_EMPHASIS,
            corner_radius=10,
            height=40,
            command=lambda: webbrowser.open("https://github.com/HydraDragonAntivirus/HydraDragonAntivirus")
        )
        github_button.place(relx=0, rely=0, x=40, y=170)
        
        self.log_outputs.append(None)
        return page

    def create_main_content(self):
        """Creates the frame to hold all pages (replaces QStackedWidget)."""
        self.main_stack_frame = customtkinter.CTkFrame(self, fg_color=COLOR_BG, corner_radius=0)
        self.main_stack_frame.grid(row=0, column=1, sticky="nsew")

        # Create pages
        self.pages = [
            self.create_status_page(self.main_stack_frame),
            self.create_task_page(
                self.main_stack_frame,
                "Updates",
                main_task_name='update_definitions',
                main_button_text="Update Definitions",
            ),
            self.create_about_page(self.main_stack_frame)
        ]
        
        # Place all pages; we'll use .place() to animate
        for page in self.pages:
            page.place(relx=1.0, rely=0, relwidth=1.0, relheight=1.0)

    # ---------------------------
    # Page switching animations
    # ---------------------------
    async def switch_page_with_animation(self, index: int):
        if self.current_page_index == index or self.is_page_animating:
            return
            
        self.is_page_animating = True
        
        current_page = self.pages[self.current_page_index]
        next_page = self.pages[index]
        
        self.current_page_index = index
        next_page.tkraise()
        
        # Place next page to the right, current page at 0
        current_page.place(relx=0.0, rely=0, relwidth=1.0, relheight=1.0)
        next_page.place(relx=1.0, rely=0, relwidth=1.0, relheight=1.0)

        start_time = self.loop_time
        duration = 0.3 # 300ms slide animation
        
        while True:
            await asyncio.sleep(0.01)
            
            elapsed = self.loop_time - start_time
            t = min(elapsed / duration, 1.0)
            
            # Ease out quad
            t = 1.0 - (1.0 - t) * (1.0 - t)
            
            current_page.place(relx=-t, rely=0, relwidth=1.0, relheight=1.0)
            next_page.place(relx=1.0 - t, rely=0, relwidth=1.0, relheight=1.0)
            
            if elapsed >= duration:
                break
                
        current_page.place(relx=1.0, rely=0, relwidth=1.0, relheight=1.0)
        next_page.place(relx=0.0, rely=0, relwidth=1.0, relheight=1.0)
        self.is_page_animating = False

    def _make_nav_handler(self, idx: int):
        """Factory to create a navigation button handler."""
        def _handler(animate=True):
            if animate:
                asyncio.create_task(self.switch_page_with_animation(idx))
            else:
                # No animation, just snap to page
                if self.pages:
                    page_to_show = self.pages[idx]
                    page_to_show.place(relx=0, rely=0, relwidth=1, relheight=1)
                    page_to_show.tkraise()
                    self.current_page_index = idx
            
            # Update button visual state
            for i, btn in enumerate(self.nav_buttons):
                if i == idx:
                    btn.configure(
                        fg_color=COLOR_ACCENT, 
                        text_color=COLOR_BG_DARK,
                        font=("Segoe UI", 13, "bold")
                    )
                else:
                    btn.configure(
                        fg_color="transparent", 
                        text_color=COLOR_TEXT,
                        font=("Segoe UI", 13, "normal")
                    )
        return _handler

    # ---------------------------
    # Sidebar
    # ---------------------------
    def create_sidebar(self):
        sidebar_frame = customtkinter.CTkFrame(
            self, 
            width=240, 
            fg_color=COLOR_BG_DARK, 
            border_width=1, 
            border_color=COLOR_BORDER,
            corner_radius=0
        )
        sidebar_frame.grid(row=0, column=0, sticky="nsw")
        sidebar_frame.grid_propagate(False)
        sidebar_frame.grid_rowconfigure(4, weight=1)

        logo_frame = customtkinter.CTkFrame(sidebar_frame, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=15, pady=25, sticky="ew")

        if os.path.exists(icon_path):
            try:
                icon_image = customtkinter.CTkImage(Image.open(icon_path), size=(40, 40))
                icon_label = customtkinter.CTkLabel(logo_frame, image=icon_image, text="")
                icon_label.pack(side="left", padx=(0, 12))
            except Exception as e:
                logger.error(f"Failed to load sidebar icon: {e}")
        
        logo_label = customtkinter.CTkLabel(
            logo_frame, 
            text="HYDRA", 
            font=("Segoe UI", 32, "bold"), 
            text_color=COLOR_ACCENT
        )
        logo_label.pack(side="left")
        
        house = '\U0001F3E0'
        sync = '\u21BB'
        info = '\u2139'
        nav_buttons_data = [(house, "Status"), (sync, "Updates"), (info, "About")]
        
        self.nav_buttons = []
        for i, (icon, name) in enumerate(nav_buttons_data):
            button = customtkinter.CTkButton(
                sidebar_frame,
                text=f"{icon}   {name}",
                font=("Segoe UI", 13, "normal"),
                fg_color="transparent",
                hover_color=COLOR_BG_LIGHT,
                text_color=COLOR_TEXT,
                corner_radius=8,
                height=40,
                anchor="w",
                command=self._make_nav_handler(i)
            )
            button.grid(row=i+1, column=0, sticky="ew", padx=15, pady=2)
            self.nav_buttons.append(button)
        
        return sidebar_frame

# ---------------------------
# Main execution - MODIFIED to remove yield handling
# ---------------------------
async def main():
    # --- Create main window ---
    window = AntivirusApp()

    # --- Start background protection (NO LONGER uses async generator) ---
    async def launch_protection():
        try:
            # Simply await the async function without iterating over yields
            await start_real_time_protection_async()
        except Exception:
            logger.exception("Real-time protection failed")

    asyncio.create_task(launch_protection())

    # --- Start main async loop ---
    await window.mainloop_async()

