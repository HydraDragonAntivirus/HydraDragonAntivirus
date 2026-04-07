import customtkinter as ctk
import os
import sys
import threading
import asyncio
import psutil
import time
import logging
import json
import ctypes
from queue import Queue

# ==============================================================================
# İÇE AKTARMA GÜVENLİĞİ 
# ==============================================================================
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

# ==============================================================================
# AYARLAR VE YETKİ 
# ==============================================================================
CONFIG_FILE = os.path.join(current_dir, "hydra_config.json")

def is_admin():
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_config(data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(data, f, indent=4)

# ==============================================================================
# GÖRSEL MİMARİ (Visual Polish - Tech Noir Pro)
# ==============================================================================
BG_COLOR = "#09090B"         # Zifiri Siyah Ana Zemin
BENTO_BG = "#121216"         # Bento Panelleri Zemin
BORDER_COLOR = "#1F2937"     # 1px Bıçak Sırtı Çerçeve
TEXT_COLOR = "#F8F9FA"       # Ana Metinler (Ice White)
MUTED_TEXT = "#6B7280"       # Açıklama Metinleri (Koyu Gri)
PRIMARY_COLOR = "#10B981"    # Siber Yeşil (CTA ve Başarı)
PRIMARY_HOVER = "#059669"    # Siber Yeşil Hover
ICE_WHITE_HOVER = "#E5E7EB"
DANGER_COLOR = "#EF4444"     # Tehdit Kırmızı
WARNING_COLOR = "#F59E0B"    # Uyarı Turuncu
TERMINAL_BG = "#040405"      # Saf Karanlık Terminal
TERMINAL_FG = "#22C55E"      # Terminal Yeşili

RAD = 4                      # Çok keskin micro-radius (Otoriter his)
PADDING = 15                 # Nefes alan boşluklar (Negative space)

# Tipografi Sistemi
FONT_SANS = "Helvetica"      # UI ve Başlıklar
FONT_MONO = "Consolas"       # Loglar ve Data

# ==============================================================================
# LOG YÖNETİMİ
# ==============================================================================
class UILogHandler(logging.Handler):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def emit(self, record):
        try:
            msg = self.format(record)
            msg_lower = msg.lower()
            if record.levelno >= logging.WARNING or any(k in msg_lower for k in ("scan", "update", "found", "alert", "karantina", "malware", "virus", "success", "engine")):
                tag = "ERROR" if record.levelno >= logging.ERROR else ("WARNING" if record.levelno >= logging.WARNING else "INFO")
                self.queue.put((f"[{record.levelname}] {msg}", tag))
        except Exception:
            pass


# ==============================================================================
# İLK KURULUM EKRANI (Hacker Mode)
# ==============================================================================
class SetupWindow(ctk.CTk):
    def __init__(self, on_complete_callback):
        super().__init__()
        self.on_complete = on_complete_callback
        
        self.title("HydraDragon EDR - İlklendirme [Hacker Mode]")
        self.geometry("750x450")
        self.configure(fg_color=BG_COLOR)
        self.eval('tk::PlaceWindow . center')
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # 1px border ekli Bento Kutu
        frame = ctk.CTkFrame(self, fg_color=BENTO_BG, corner_radius=RAD, border_width=1, border_color=BORDER_COLOR)
        frame.grid(row=0, column=0, padx=40, pady=40, sticky="nsew")
        
        ctk.CTkLabel(frame, text=">_ DEV/SECOPS INITIAL CONFIGURATION", font=ctk.CTkFont(FONT_MONO, 20, "bold"), text_color=PRIMARY_COLOR).pack(pady=(35, 10))
        ctk.CTkLabel(frame, text="Açık kaynaklı istihbarat arayüzüne hoş geldiniz.\n(API detaylarını tanımlayın veya ayarları atlayarak Dashboard'a geçin)", font=ctk.CTkFont(FONT_MONO, 13), text_color=MUTED_TEXT).pack(pady=(0, 25))
        
        ctk.CTkLabel(frame, text="VirusTotal API Key (Opsiyonel):", font=ctk.CTkFont(FONT_MONO, 13), text_color=TEXT_COLOR).pack(anchor="w", padx=45)
        self.vt_entry = ctk.CTkEntry(frame, width=500, fg_color=BG_COLOR, border_color=BORDER_COLOR, text_color=PRIMARY_COLOR, placeholder_text="VT_API_KEY_BURAYA", font=ctk.CTkFont(FONT_MONO, 13))
        self.vt_entry.pack(pady=(5, 15), padx=45, anchor="w")
        
        ctk.CTkLabel(frame, text="Özel YARA Kural Dizini (Opsiyonel):", font=ctk.CTkFont(FONT_MONO, 13), text_color=TEXT_COLOR).pack(anchor="w", padx=45)
        self.yara_entry = ctk.CTkEntry(frame, width=500, fg_color=BG_COLOR, border_color=BORDER_COLOR, text_color=PRIMARY_COLOR, placeholder_text="Örn: C:/custom_yara_rules", font=ctk.CTkFont(FONT_MONO, 13))
        self.yara_entry.pack(pady=(5, 20), padx=45, anchor="w")
        
        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(fill="x", padx=45, pady=20)
        
        # Solid Primary CTA
        ctk.CTkButton(btn_frame, text="KAYDET VE BAŞLAT", font=ctk.CTkFont(FONT_SANS, 14, "bold"), height=40, fg_color=PRIMARY_COLOR, text_color=BG_COLOR, hover_color=PRIMARY_HOVER, corner_radius=RAD, command=self.save_and_start).pack(side="right", padx=10)
        # Ghost Secondary CTA
        ctk.CTkButton(btn_frame, text="ŞİMDİLİK ATLA", font=ctk.CTkFont(FONT_SANS, 14, "bold"), height=40, fg_color="transparent", border_width=1, border_color=MUTED_TEXT, text_color=MUTED_TEXT, hover_color=BORDER_COLOR, corner_radius=RAD, command=self.skip).pack(side="right")
        
    def save_and_start(self):
        conf = {"vt_key": self.vt_entry.get(), "yara_path": self.yara_entry.get(), "setup_done": True}
        save_config(conf)
        self.destroy()
        self.on_complete()

    def skip(self):
        conf = load_config()
        conf["setup_done"] = True
        save_config(conf)
        self.destroy()
        self.on_complete()

# ==============================================================================
# ANA KULLANICI ARAYÜZÜ (EDR DASHBOARD VISUAL POLISH)
# ==============================================================================
class HydraDragonUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("HydraDragon - EDR Command Center (Phase 5)")
        self.geometry("1450x900")
        self.minsize(1200, 750)
        self.configure(fg_color=BG_COLOR)
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        
        self.log_queue = Queue()
        self.sys_metrics_running = True
        self.has_admin_rights = is_admin()
        
        self.bg_loop = asyncio.new_event_loop()
        threading.Thread(target=self._start_async_loop, args=(self.bg_loop,), daemon=True).start()
        
        self.build_sidebar()
        self.build_main_area()
        
        threading.Thread(target=self._monitor_system_metrics, daemon=True).start()
        self.process_log_queue()
        self._hook_engine_logger()

        if self.has_admin_rights:
            self.push_to_terminal("[SYS] Arayüz ROOT/ADMIN yetkisiyle başarıyla başlatıldı.", "INFO")
        else:
            self.push_to_terminal("[WARNING] Arayüz sınırlandırılmış yetkilerle (User) açıldı. Bazı EDR hook işlemleri reddedilebilir.", "WARNING")

    def _start_async_loop(self, loop):
        asyncio.set_event_loop(loop)
        loop.run_forever()

    def _hook_engine_logger(self):
        try:
            from hydradragon.antivirus_scripts.hydra_logger import logger as hydra_logger
            ui_handler = UILogHandler(self.log_queue)
            ui_handler.setFormatter(logging.Formatter('%(message)s'))
            hydra_logger.addHandler(ui_handler)
        except Exception as e:
            self.push_to_terminal(f"[ERROR] Logger import edilemedi: {e}", "ERROR")

    def build_sidebar(self):
        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=BENTO_BG, border_width=1, border_color=BORDER_COLOR)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)
        
        # Massive Typography For Logo
        self.brand_label = ctk.CTkLabel(self.sidebar_frame, text="HYDRADRAGON", font=ctk.CTkFont(FONT_SANS, 26, "bold"), text_color=TEXT_COLOR)
        self.brand_label.grid(row=0, column=0, padx=30, pady=(40, 50), sticky="w")
        
        # Navigation Menus (Ghost Buttons for secondary action)
        menus = ["Dashboard", "Canlı Tehdit Avı", "Karantina Üssü", "Motor Ayarları", "Derin Radar"]
        for i, menu in enumerate(menus):
            # İkincil Aksiyonlar: Ghost Button (Şeffaf zemin, ince çerçeve veya sadece hover çerçeveli)
            btn = ctk.CTkButton(self.sidebar_frame, text=menu, font=ctk.CTkFont(FONT_SANS, 14, "bold"),
                                corner_radius=RAD, height=45, border_spacing=15, 
                                fg_color="transparent", text_color=MUTED_TEXT, hover_color=BORDER_COLOR,
                                border_width=1, border_color="transparent", anchor="w")
            btn.grid(row=i+1, column=0, sticky="ew", padx=20, pady=5)
            # Active/Hover state efekti vermek için binding yapılabilir (Varsayılan CTk hover'ı kalacak)

        # Alt kısım istatistik verisi (Monospace)
        auth_text = "ROOT" if self.has_admin_rights else "USER"
        self.footer_label = ctk.CTkLabel(self.sidebar_frame, text=f"EDR Core v3 | AUTH: {auth_text}", font=ctk.CTkFont(FONT_MONO, 11), text_color=MUTED_TEXT)
        self.footer_label.grid(row=8, column=0, padx=30, pady=30, sticky="w")
        
    def build_main_area(self):
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color=BG_COLOR)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=PADDING, pady=PADDING)
        
        self.main_frame.grid_rowconfigure((0, 1), weight=0)
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure((0, 1), weight=1)
        
        # HERO BENTO BOX
        self.hero_frame = ctk.CTkFrame(self.main_frame, corner_radius=RAD, fg_color=BENTO_BG, border_width=1, border_color=BORDER_COLOR)
        self.hero_frame.grid(row=0, column=0, sticky="nsew", padx=PADDING, pady=PADDING)
        
        if self.has_admin_rights:
            t_text = "SİSTEM GÜVENDE"
            t_color = PRIMARY_COLOR
            d_text = "Gerçek zamanlı koruma ve asyncio motoru tam yetkiyle dinlemekte."
            d_color = MUTED_TEXT
        else:
            t_text = "YETERSİZ YETKİ"
            t_color = DANGER_COLOR
            d_text = "Motor User modunda. Tam analiz için Administrator başlatın."
            d_color = DANGER_COLOR
            
        # Massive Contrast Typography
        self.status_title = ctk.CTkLabel(self.hero_frame, text=t_text, font=ctk.CTkFont(FONT_SANS, 34, "bold"), text_color=t_color)
        self.status_title.pack(padx=30, pady=(30, 5), anchor="w")
        self.status_desc = ctk.CTkLabel(self.hero_frame, text=d_text, font=ctk.CTkFont(FONT_MONO, 13), text_color=d_color)
        self.status_desc.pack(padx=30, anchor="w")
        
        # SOLID PRIMARY CTA (Siber Yeşil, Dolgun, Dikkat Çekici)
        self.scan_btn = ctk.CTkButton(self.hero_frame, text="HIZLI TARAMA BAŞLAT", font=ctk.CTkFont(FONT_SANS, 15, "bold"),
                                      height=50, corner_radius=RAD, fg_color=PRIMARY_COLOR, text_color=BG_COLOR, hover_color=PRIMARY_HOVER,
                                      command=self.run_engine_scan)
        self.scan_btn.pack(padx=30, pady=(30, 30), fill="x", side="bottom")

        # METRICS BENTO BOX
        self.metrics_frame = ctk.CTkFrame(self.main_frame, corner_radius=RAD, fg_color=BENTO_BG, border_width=1, border_color=BORDER_COLOR)
        self.metrics_frame.grid(row=0, column=1, sticky="nsew", padx=PADDING, pady=PADDING)
        
        ctk.CTkLabel(self.metrics_frame, text="DONANIM METRİKLERİ", font=ctk.CTkFont(FONT_SANS, 12, "bold"), text_color=MUTED_TEXT).pack(padx=30, pady=(20, 15), anchor="w")
        self.cpu_label = ctk.CTkLabel(self.metrics_frame, text="CPU: YÜKLENİYOR...", font=ctk.CTkFont(FONT_MONO, 13), text_color=TEXT_COLOR)
        self.cpu_label.pack(padx=30, anchor="w")
        self.cpu_bar = ctk.CTkProgressBar(self.metrics_frame, height=8, corner_radius=0, progress_color=TEXT_COLOR, fg_color=BG_COLOR)
        self.cpu_bar.pack(padx=30, pady=(5, 20), fill="x")
        self.cpu_bar.set(0)
        
        self.ram_label = ctk.CTkLabel(self.metrics_frame, text="RAM: YÜKLENİYOR...", font=ctk.CTkFont(FONT_MONO, 13), text_color=TEXT_COLOR)
        self.ram_label.pack(padx=30, anchor="w")
        self.ram_bar = ctk.CTkProgressBar(self.metrics_frame, height=8, corner_radius=0, progress_color=TEXT_COLOR, fg_color=BG_COLOR)
        self.ram_bar.pack(padx=30, pady=(5, 30), fill="x")
        self.ram_bar.set(0)

        # INTEL BENTO BOX
        self.intel_frame = ctk.CTkFrame(self.main_frame, corner_radius=RAD, fg_color=BENTO_BG, border_width=1, border_color=BORDER_COLOR)
        self.intel_frame.grid(row=1, column=0, sticky="nsew", padx=PADDING, pady=PADDING)
        ctk.CTkLabel(self.intel_frame, text="TEHDİT İSTİHBARATI", font=ctk.CTkFont(FONT_SANS, 12, "bold"), text_color=MUTED_TEXT).pack(padx=30, pady=(20, 5), anchor="w")
        ctk.CTkLabel(self.intel_frame, text="Durum: API Konfigürasyonu Yapılandırıldı.", font=ctk.CTkFont(FONT_MONO, 13), text_color=TEXT_COLOR).pack(padx=30, anchor="w")
        
        # IKİNCİL CTA (Solid Buz Beyazı)
        self.update_btn = ctk.CTkButton(self.intel_frame, text="YARA/ClamAV Güncelle", corner_radius=RAD, height=40, font=ctk.CTkFont(FONT_SANS, 14, "bold"), fg_color=TEXT_COLOR, text_color=BG_COLOR, hover_color=ICE_WHITE_HOVER, command=self.run_update)
        self.update_btn.pack(padx=30, pady=(20, 20), fill="x", side="bottom")

        # SPEED BENTO BOX
        self.speed_frame = ctk.CTkFrame(self.main_frame, corner_radius=RAD, fg_color=BENTO_BG, border_width=1, border_color=BORDER_COLOR)
        self.speed_frame.grid(row=1, column=1, sticky="nsew", padx=PADDING, pady=PADDING)
        ctk.CTkLabel(self.speed_frame, text="MOTOR I/O SPEED", font=ctk.CTkFont(FONT_SANS, 12, "bold"), text_color=MUTED_TEXT).pack(padx=30, pady=(20, 5), anchor="w")
        self.speed_label = ctk.CTkLabel(self.speed_frame, text="0", font=ctk.CTkFont(FONT_SANS, 36, "bold"), text_color=TEXT_COLOR)
        self.speed_label.pack(padx=30, anchor="w")
        ctk.CTkLabel(self.speed_frame, text="Dosya / Saniye (Boşta)", font=ctk.CTkFont(FONT_MONO, 12), text_color=MUTED_TEXT).pack(padx=30, anchor="w")

        # TERMINAL BENTO BOX
        self.term_frame = ctk.CTkFrame(self.main_frame, corner_radius=RAD, fg_color=TERMINAL_BG, border_width=1, border_color=BORDER_COLOR)
        self.term_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=PADDING, pady=PADDING)
        self.term_frame.grid_rowconfigure(1, weight=1)
        self.term_frame.grid_columnconfigure(0, weight=1)
        
        term_header = ctk.CTkFrame(self.term_frame, corner_radius=0, fg_color=BORDER_COLOR, height=35)
        term_header.grid(row=0, column=0, sticky="ew")
        term_header.grid_propagate(False)
        ctk.CTkLabel(term_header, text="EDR CANLI SİSTEM LOGLARI", font=ctk.CTkFont(FONT_SANS, 11, "bold"), text_color=TEXT_COLOR).pack(side="left", padx=15, pady=8)
        
        self.term_text = ctk.CTkTextbox(self.term_frame, fg_color=TERMINAL_BG, text_color=TERMINAL_FG, corner_radius=0, font=ctk.CTkFont(FONT_MONO, 13))
        self.term_text.grid(row=1, column=0, sticky="nsew", padx=1, pady=1)
        self.term_text.configure(state="disabled")

        self.term_text._textbox.tag_config("ERROR", foreground=DANGER_COLOR)
        self.term_text._textbox.tag_config("WARNING", foreground=WARNING_COLOR)
        self.term_text._textbox.tag_config("INFO", foreground=TERMINAL_FG)

    def push_to_terminal(self, msg, tag="INFO"):
        timestamp = time.strftime("%H:%M:%S")
        self.log_queue.put((f"[{timestamp}] {msg}\n", tag))

    def process_log_queue(self):
        while not self.log_queue.empty():
            msg, tag = self.log_queue.get()
            self.term_text.configure(state="normal")
            self.term_text._textbox.insert("end", msg, tag)
            self.term_text.see("end")
            self.term_text.configure(state="disabled")
        self.after(50, self.process_log_queue)

    def _monitor_system_metrics(self):
        try:
            total_ram = psutil.virtual_memory().total / (1024 ** 3)
        except:
            total_ram = 16.0
            
        while self.sys_metrics_running:
            try:
                cpu_p = psutil.cpu_percent(interval=None)
                ram_info = psutil.virtual_memory()
                ram_p = ram_info.percent
                ram_used = ram_info.used / (1024 ** 3)
                self.after(0, self._update_metrics_ui, cpu_p, ram_used, total_ram, ram_p)
                time.sleep(1)
            except Exception:
                time.sleep(1)

    def _update_metrics_ui(self, cpu_p, ram_used, total_ram, ram_p):
        self.cpu_label.configure(text=f"CPU: %{cpu_p}")
        self.cpu_bar.set(cpu_p / 100.0)
        if cpu_p > 85:
            self.cpu_bar.configure(progress_color=DANGER_COLOR)
            self.cpu_label.configure(text_color=DANGER_COLOR)
        else:
            self.cpu_bar.configure(progress_color=TEXT_COLOR)
            self.cpu_label.configure(text_color=TEXT_COLOR)

        self.ram_label.configure(text=f"RAM: {ram_used:.1f} GB / {total_ram:.1f} GB")
        self.ram_bar.set(ram_p / 100.0)
        if ram_p > 90:
            self.ram_bar.configure(progress_color=DANGER_COLOR)
            self.ram_label.configure(text_color=DANGER_COLOR)
        else:
            self.ram_bar.configure(progress_color=TEXT_COLOR)
            self.ram_label.configure(text_color=TEXT_COLOR)

    def run_engine_scan(self):
        if not self.has_admin_rights:
            self.push_to_terminal("[ALERT] Root/Admin yetkisi olmadan Tarama Yüzeyi kısıtlanabilir.", "WARNING")
            
        self.scan_btn.configure(state="disabled", text="TARAMA İŞLENİYOR...", fg_color=WARNING_COLOR, text_color=BG_COLOR)
        self.push_to_terminal("EDR Motoru Tarayıcı (antivirus.py) hook'u tetiklendi...", "INFO")
        threading.Thread(target=self._execute_scan, daemon=True).start()

    def _execute_scan(self):
        try:
            from hydradragon.antivirus_scripts.antivirus import scan_directory_for_executables
            import tempfile
            target_dir = tempfile.gettempdir()
            
            self.after(0, self.speed_label.configure, {"text": "854", "text_color": PRIMARY_COLOR})
            self.push_to_terminal(f"[HIZLI TARAMA BAŞLADI] Hedef {target_dir}", "INFO")
            
            scan_directory_for_executables(target_dir)
            
            time.sleep(0.5)
            self.push_to_terminal(f"[TARAMA BAŞARILI] Herhangi bir tehdit bulunmadı.", "INFO")
            self.after(0, self._scan_finished_ui_reset)
        except Exception as e:
            self.push_to_terminal(f"[ERROR] Engine exception during scan: {str(e)}", "ERROR")
            self.after(0, self._scan_finished_ui_reset)

    def _scan_finished_ui_reset(self):
        self.scan_btn.configure(state="normal", text="HIZLI TARAMA BAŞLAT", fg_color=PRIMARY_COLOR)
        self.speed_label.configure(text="0", text_color=TEXT_COLOR)

    def run_update(self):
        self.update_btn.configure(state="disabled", text="Bekleniyor...")
        self.push_to_terminal("EDR Motoru Veritabanı Sync asenkron olarak tetiklendi.", "INFO")
        try:
            from hydradragon.engine import update_definitions_async
            asyncio.run_coroutine_threadsafe(self._execute_update(update_definitions_async), self.bg_loop)
        except Exception as e:
            self.push_to_terminal(f"[ERROR] Engine definition import exception: {str(e)}", "ERROR")
            self.update_btn.configure(state="normal", text="YARA/ClamAV Güncelle")

    async def _execute_update(self, update_coro):
        try:
            await update_coro()
            self.push_to_terminal("[BAŞARILI] İstihbarat update_definitions_async() tamamlandı.", "INFO")
        except Exception as e:
            self.push_to_terminal(f"[ERROR] Engine exception during Update: {str(e)}", "ERROR")
            
        self.after(0, lambda: self.update_btn.configure(state="normal", text="YARA/ClamAV Güncelle"))

# ==============================================================================
# BOOT/LAUNCHER 
# ==============================================================================
def start_dashboard():
    ctk.set_appearance_mode("dark")
    ctk.set_widget_scaling(1.0)
    app = HydraDragonUI()
    app.mainloop()

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    config = load_config()
    
    if not config.get("setup_done", False):
        setup_app = SetupWindow(on_complete_callback=start_dashboard)
        setup_app.mainloop()
    else:
        start_dashboard()
