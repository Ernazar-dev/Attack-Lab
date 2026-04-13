"""
config.py — Barcha sozlamalar (v4 — TO'LIQ TUZATILGAN)

Tuzatishlar:
  - MIN_RPS_THRESHOLD hardcode emas, config da
  - ANALYSIS_WINDOW_SEC env orqali o'zgartiriladi
  - EXCLUDED_PATHS frozenset (immutable, tezroq)
  - Yangi: LOG_LEVEL, MAX_IP_TRACKER sozlamalari
"""
import os
import codecs


def load_env(path=".env"):
    try:
        with codecs.open(path, "r", encoding="utf-8-sig") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                os.environ.setdefault(
                    key.strip(),
                    value.strip().strip('"').strip("'")
                )
    except FileNotFoundError:
        pass


load_env()

# --- Flask ---
SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "ids-secret-key-2024")
PORT       = int(os.getenv("FLASK_PORT", 5000))
DEBUG      = os.getenv("FLASK_DEBUG", "false").lower() == "true"

# --- Database ---
BASE_DIR     = os.path.abspath(os.path.dirname(__file__))
DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "ids_database.db")

# --- ML ---
MODEL_PATH   = os.getenv("MODEL_PATH",   "network_model.pkl")
SCALER_PATH  = os.getenv("SCALER_PATH",  "scaler.pkl")
ENCODER_PATH = os.getenv("ENCODER_PATH", "label_encoder.pkl")

FEATURES = [
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    "flow_byts_s",
    "flow_pkts_s",
    "pkt_len_mean",
    "fwd_iat_mean",
    "fin_flag_cnt",
]

# --- IDS/IPS sozlamalari ---
# Sliding window uzunligi (soniya). Kichikroq = tezroq aniqlash, ko'proq false positive
ANALYSIS_WINDOW_SEC = float(os.getenv("ANALYSIS_WINDOW_SEC", 3.0))

# Minimum req/s chegarasi — bundan past traffic tahlil qilinmaydi (warming up)
MIN_RPS_THRESHOLD   = float(os.getenv("MIN_RPS_THRESHOLD", 3.0))

# IP tracker timeout (soniya) — bu vaqtdan keyin eskirgan IP yozuvlari o'chiriladi
TRACKER_TIMEOUT_SEC = int(os.getenv("TRACKER_TIMEOUT_SEC", 300))

# Har necha so'rovda bir eskirgan IP'larni tozalash
CLEANUP_INTERVAL    = int(os.getenv("CLEANUP_INTERVAL", 100))

# Hujum aniqlanganda qaytariladigan HTTP status kodi
ATTACK_HTTP_CODE    = 403

# Tahlildan chiqariladigan yo'llar (frozenset — immutable va tezroq lookup)
EXCLUDED_PATHS = frozenset({
    "/",
    "/favicon.ico",
    "/api/logs",
    "/api/stats",
    "/api/health",
    "/api/debug/features",
    # "/api/test" — intentionally NOT excluded: attacker shu endpointga uradi
})

# Log darajasi
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# IP tracker maksimal hajmi (xotira nazorati)
MAX_IP_TRACKER = int(os.getenv("MAX_IP_TRACKER", 10_000))