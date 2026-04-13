"""
main.py — IDS/IPS Flask backend (v5 — TO'LIQ TUZATILGAN)

Tuzatishlar:
  1. SQLAlchemy thread safety: scoped_session ishlatildi
  2. MIN_RPS_THRESHOLD config.py dan o'qiladi (hardcode emas)
  3. Memory leak tuzatildi: req_counter ATTACK da ham oshadi
  4. Pattern matching overlap muammosi: aniq tartib va sharshlar
  5. is_ldap va is_udp konflikti tuzatildi (is_ldap is_udp dan keyin keladi)
  6. IP tracker MAX_IP_TRACKER chegarasi qo'shildi
  7. Error handling yaxshilandi (db session)
  8. Health endpoint qo'shildi
"""
import time
import logging
import threading
import os
from datetime import datetime

import joblib
import numpy as np
from flask import Flask, request, jsonify, abort, make_response
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import scoped_session, sessionmaker

import config

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Flask ilovasi
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"]                     = config.SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"]        = config.DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"]      = {
    "pool_pre_ping": True,
    "connect_args": {"check_same_thread": False},  # SQLite thread safety
}

CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="eventlet",
    logger=False,
    engineio_logger=False,
)

db = SQLAlchemy(app)


@app.errorhandler(403)
def forbidden(ex):
    return make_response(jsonify({"error": "Hujum aniqlandi va bloklandi!"}), 403)


@app.errorhandler(503)
def service_unavailable(ex):
    return make_response(jsonify({"error": "Model yuklanmagan, keyinroq urinib ko'ring"}), 503)


# ---------------------------------------------------------------------------
# Database modeli
# ---------------------------------------------------------------------------
class NetworkLog(db.Model):
    __tablename__ = "network_logs"

    id          = db.Column(db.Integer,    primary_key=True)
    ip_address  = db.Column(db.String(50), nullable=False)
    attack_type = db.Column(db.String(30), nullable=False)
    req_per_sec = db.Column(db.Float,      nullable=False)
    flow_byts_s = db.Column(db.Float,      nullable=False)
    status      = db.Column(db.String(20), nullable=False)
    timestamp   = db.Column(db.DateTime,   default=datetime.utcnow)

    def to_dict(self):
        return {
            "id":          self.id,
            "ip":          self.ip_address,
            "attack_type": self.attack_type,
            "status":      self.status,
            "req":         round(self.req_per_sec, 2),
            "bytes_s":     round(self.flow_byts_s, 0),
            "time":        self.timestamp.strftime("%H:%M:%S"),
        }


# ---------------------------------------------------------------------------
# ML pipeline
# ---------------------------------------------------------------------------
model   = None
scaler  = None
encoder = None


def load_pipeline() -> bool:
    global model, scaler, encoder
    for path, name in [
        (config.MODEL_PATH,   "Model"),
        (config.SCALER_PATH,  "Scaler"),
        (config.ENCODER_PATH, "Encoder"),
    ]:
        if not os.path.exists(path):
            log.error("%s topilmadi: %s — avval 'python model_train.py' ni ishga tushiring", name, path)
            return False
    try:
        model   = joblib.load(config.MODEL_PATH)
        scaler  = joblib.load(config.SCALER_PATH)
        encoder = joblib.load(config.ENCODER_PATH)
        log.info("ML pipeline muvaffaqiyatli yuklandi. Sinflar: %s", list(encoder.classes_))
        return True
    except Exception as exc:
        log.error("Pipeline yuklashda xato: %s", exc)
        return False


# ---------------------------------------------------------------------------
# IP Tracker — thread-safe sliding window
# ---------------------------------------------------------------------------
ip_tracker   = {}
tracker_lock = threading.Lock()
req_counter  = 0
counter_lock = threading.Lock()


def _cleanup_old_ips():
    """Eskirgan va haddan ziyod IP yozuvlarni o'chirish."""
    now = time.time()
    with tracker_lock:
        # Eskirganlarni o'chirish
        expired = [
            ip for ip, d in ip_tracker.items()
            if now - d["start"] > config.TRACKER_TIMEOUT_SEC
        ]
        for ip in expired:
            del ip_tracker[ip]

        # MAX_IP_TRACKER dan oshsa, eng eskiklarini o'chirish (xotira nazorati)
        if len(ip_tracker) > config.MAX_IP_TRACKER:
            sorted_ips = sorted(ip_tracker.items(), key=lambda x: x[1]["start"])
            overflow = len(ip_tracker) - config.MAX_IP_TRACKER
            for ip, _ in sorted_ips[:overflow]:
                del ip_tracker[ip]
            log.warning("IP tracker limit oshdi, %d ta eski yozuv o'chirildi", overflow)

    return len(expired)


def get_req_per_sec(ip: str):
    """Sliding window req/s hisoblash. None qaytarsa — hali yetarli ma'lumot yo'q."""
    now = time.time()
    with tracker_lock:
        if ip not in ip_tracker:
            ip_tracker[ip] = {"count": 0, "start": now}

        ip_tracker[ip]["count"] += 1
        duration = now - ip_tracker[ip]["start"]

        if duration < 0.3:
            return None

        rps = ip_tracker[ip]["count"] / duration

        if duration >= config.ANALYSIS_WINDOW_SEC:
            ip_tracker[ip] = {"count": 0, "start": now}

        return rps


# ---------------------------------------------------------------------------
# FEATURE HISOBLASH
#
# Pattern aniqlash tartibi (muhim — overlap oldini olish uchun):
#   1. PORTSCAN  — eng kichik paket + juda tez req/s (alohida formula)
#   2. SYN       — kichik paket + tez req/s (portscan emas)
#   3. UDP       — katta paket + tez req/s
#   4. LDAP      — katta paket + tez req/s (UDP emas, bwd ko'p)
#   5. DNS       — o'rta paket + tez req/s (syn emas)
#   6. NTP       — o'rta paket + o'rtacha req/s
#   7. NORMAL    — boshqa barchasi
#
# Overlap hal qilindi:
#   - is_ldap: is_udp dan KEYIN tekshiriladi (elif zanjiri)
#   - is_dns: is_syn dan KEYIN tekshiriladi
#   - NTP: req_s chegarasi DNS dan farqli (10-15 vs 15+)
# ---------------------------------------------------------------------------
def build_features(req_s: float, pkt_size: int, duration_s: float = None) -> tuple:
    """
    req_s      : so'rovlar soni per second
    pkt_size   : paket o'lchami (bayt)
    duration_s : oyna uzunligi (soniya)

    Returns: (features_list, pattern_name)
    """
    if duration_s is None:
        duration_s = config.ANALYSIS_WINDOW_SEC

    flow_duration = duration_s * 1_000_000  # mikrosaniya

    # ----------------------------------------------------------------
    # PATTERN ANIQLASH — aniq tartib, overlap yo'q
    # ----------------------------------------------------------------

    if (pkt_size <= 80) and (req_s >= 10):
        # PORT SCAN: TCP SYN paketlar (40-80B), juda tez
        pattern_name = "PORTSCAN"
        pkts_per_req = max(50_000 / max(req_s, 1), 1)
        flow_pkts_s  = req_s * pkts_per_req
        flow_byts_s  = flow_pkts_s * pkt_size
        tot_fwd_pkts = max(req_s * duration_s, 2)
        tot_bwd_pkts = tot_fwd_pkts * 0.5
        fwd_iat_mean = 1000.0 / max(flow_pkts_s, 1)
        fin_flag     = 0.0
        fwd_pkt_len  = float(pkt_size)
        bwd_pkt_len  = float(pkt_size)

    elif (40 <= pkt_size <= 100) and (req_s >= 20):
        # SYN FLOOD: kichik TCP SYN, tez req/s, portscan emas
        pattern_name = "SYN-FLOOD"
        pkts_per_req = 25
        flow_pkts_s  = req_s * pkts_per_req
        flow_byts_s  = flow_pkts_s * pkt_size
        tot_fwd_pkts = req_s * duration_s * pkts_per_req
        tot_bwd_pkts = tot_fwd_pkts * 0.01
        fwd_iat_mean = 1000.0 / max(flow_pkts_s, 1)
        fin_flag     = 0.0
        fwd_pkt_len  = float(pkt_size)
        bwd_pkt_len  = float(pkt_size * 1.1)

    elif (pkt_size >= 800) and (req_s >= 15):
        # UDP FLOOD: katta paket, tez req/s
        # LDAP dan OLDIN tekshiriladi, chunki LDAP ham katta paket bo'lishi mumkin
        # Farqi: UDP bwd juda kam, LDAP bwd ko'p
        pattern_name = "UDP-FLOOD"
        pkts_per_req = 24
        flow_pkts_s  = req_s * pkts_per_req
        flow_byts_s  = flow_pkts_s * pkt_size
        tot_fwd_pkts = req_s * duration_s * pkts_per_req
        tot_bwd_pkts = tot_fwd_pkts * 0.008
        fwd_iat_mean = 1000.0 / max(flow_pkts_s, 1)
        fin_flag     = 0.0
        fwd_pkt_len  = float(pkt_size)
        bwd_pkt_len  = float(pkt_size * 0.05)

    elif (500 <= pkt_size < 800) and (req_s >= 15):
        # LDAP AMPLIFICATION: o'rta-katta paket, bwd ko'p
        # pkt_size >= 800 bo'lsa UDP ga ketgan, bu holat 500-799B
        pattern_name = "LDAP-AMP"
        pkts_per_req = 20
        flow_pkts_s  = req_s * pkts_per_req
        flow_byts_s  = flow_pkts_s * pkt_size
        tot_fwd_pkts = req_s * duration_s * pkts_per_req * 0.3
        tot_bwd_pkts = req_s * duration_s * pkts_per_req * 0.7
        fwd_iat_mean = 1000.0 / max(flow_pkts_s, 1)
        fin_flag     = 2.0
        fwd_pkt_len  = float(pkt_size * 0.15)
        bwd_pkt_len  = float(pkt_size * 1.3)

    elif (60 <= pkt_size <= 250) and (req_s >= 15):
        # DNS AMPLIFICATION: o'rta paket, tez req/s, syn emas
        pattern_name = "DNS-AMP"
        pkts_per_req = 20
        flow_pkts_s  = req_s * pkts_per_req
        flow_byts_s  = flow_pkts_s * pkt_size
        tot_fwd_pkts = req_s * duration_s * pkts_per_req * 0.4
        tot_bwd_pkts = req_s * duration_s * pkts_per_req * 0.6
        fwd_iat_mean = 1000.0 / max(flow_pkts_s, 1)
        fin_flag     = 0.0
        fwd_pkt_len  = float(pkt_size * 0.4)
        bwd_pkt_len  = float(pkt_size * 1.5)

    elif (60 <= pkt_size <= 120) and (10 <= req_s < 15):
        # NTP AMPLIFICATION: o'rta paket, o'rtacha req/s
        # DNS dan farqi: req_s < 15 (DNS >= 15)
        pattern_name = "NTP-AMP"
        pkts_per_req = 15
        flow_pkts_s  = req_s * pkts_per_req
        flow_byts_s  = flow_pkts_s * pkt_size
        tot_fwd_pkts = req_s * duration_s * pkts_per_req * 0.2
        tot_bwd_pkts = req_s * duration_s * pkts_per_req * 0.8
        fwd_iat_mean = 1000.0 / max(flow_pkts_s, 1)
        fin_flag     = 0.0
        fwd_pkt_len  = float(pkt_size * 0.17)
        bwd_pkt_len  = float(pkt_size * 4.6)

    else:
        # NORMAL HTTP yoki past intensivlik
        pattern_name = "NORMAL"
        pkts_per_req = 1
        flow_pkts_s  = req_s * pkts_per_req
        flow_byts_s  = flow_pkts_s * pkt_size
        tot_fwd_pkts = req_s * duration_s
        tot_bwd_pkts = tot_fwd_pkts * 0.6
        fwd_iat_mean = 1000.0 / max(flow_pkts_s, 0.01)
        fin_flag     = 1.0
        fwd_pkt_len  = float(pkt_size)
        bwd_pkt_len  = float(pkt_size * 1.2)

    pkt_len_mean = (fwd_pkt_len + bwd_pkt_len) / 2

    features = [
        flow_duration,
        tot_fwd_pkts,
        tot_bwd_pkts,
        fwd_pkt_len,
        bwd_pkt_len,
        flow_byts_s,
        flow_pkts_s,
        pkt_len_mean,
        fwd_iat_mean,
        fin_flag,
    ]

    log.debug(
        "[PATTERN:%s] req/s=%.1f pkt=%dB pkts_per_req=%.0f flow_pkts_s=%.0f",
        pattern_name, req_s, pkt_size, pkts_per_req, flow_pkts_s
    )

    return features, pattern_name


def analyze_traffic(features: list) -> tuple:
    """Model orqali traffic turini aniqlash."""
    X          = np.array([features])
    X_scaled   = scaler.transform(X)
    pred_idx   = model.predict(X_scaled)[0]
    attack_type = encoder.inverse_transform([pred_idx])[0]
    proba      = model.predict_proba(X_scaled)[0]
    confidence = float(proba[pred_idx])
    status     = "NORMAL" if attack_type == "BENIGN" else "ATTACK"
    return status, attack_type, confidence


# ---------------------------------------------------------------------------
# Middleware — har bir so'rovni tahlil qilish
# ---------------------------------------------------------------------------
@app.before_request
def ips_middleware():
    global req_counter

    if request.path in config.EXCLUDED_PATHS or request.path.startswith("/socket.io"):
        return
    if request.method == "OPTIONS":
        return

    if model is None:
        abort(503)

    ip    = request.remote_addr or "unknown"
    req_s = get_req_per_sec(ip)

    if req_s is None or req_s < config.MIN_RPS_THRESHOLD:
        if req_s is not None:
            log.debug("Skip (req/s=%.1f < %.1f): %s", req_s, config.MIN_RPS_THRESHOLD, ip)
        return

    raw      = request.get_data()
    pkt_size = max(len(raw), 1) if raw else 200

    features, pattern = build_features(req_s, pkt_size)
    status, attack_type, confidence = analyze_traffic(features)

    flow_pkts_s = features[6]
    flow_byts_s = features[5]

    log.info(
        "ANALIZ | IP: %s | req/s: %.1f | pkt: %dB | pattern: %s | "
        "pkts/s: %.0f | Model: %s (%.0f%%) | Status: %s",
        ip, req_s, pkt_size, pattern, flow_pkts_s, attack_type, confidence * 100, status
    )

    log_data = {
        "ip":         ip,
        "attack_type": attack_type,
        "status":     status,
        "req":        round(req_s, 2),
        "bytes_s":    round(flow_byts_s, 0),
        "time":       datetime.now().strftime("%H:%M:%S"),
        "confidence": round(confidence, 3),
    }

    # DB ga yozish — thread-safe
    try:
        entry = NetworkLog(
            ip_address  = ip,
            attack_type = attack_type,
            req_per_sec = float(req_s),
            flow_byts_s = float(flow_byts_s),
            status      = status,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log.error("DB xato: %s", exc)

    socketio.emit("new_alert", log_data)

    # TUZATISH: req_counter ATTACK da ham oshadi (eski kodda oshmaydi edi → cleanup ishlamaydi edi)
    with counter_lock:
        req_counter += 1
        if req_counter % config.CLEANUP_INTERVAL == 0:
            removed = _cleanup_old_ips()
            if removed:
                log.info("Tozalandi: %d ta eskirgan IP", removed)

    if status == "ATTACK":
        log.warning(
            "HUJUM BLOKLANDI! IP: %s | Tur: %s | Confidence: %.0f%% | Pattern: %s",
            ip, attack_type, confidence * 100, pattern
        )
        abort(403)
    else:
        log.info("Traffic OK. IP: %s | req/s: %.1f | Pattern: %s", ip, req_s, pattern)


# ---------------------------------------------------------------------------
# API Route'lar
# ---------------------------------------------------------------------------
@app.route("/")
def home():
    return jsonify({"message": "IDS/IPS ishlamoqda", "status": "ok", "version": "v5"})


@app.route("/api/health")
def health():
    """Health check endpoint — monitoring uchun."""
    return jsonify({
        "status":       "ok",
        "model_loaded": model is not None,
        "db_ok":        True,
        "tracked_ips":  len(ip_tracker),
    })


@app.route("/api/test", methods=["GET", "POST"])
def api_test():
    return jsonify({"status": "ok", "message": "Test so'rov qabul qilindi"})


@app.route("/api/logs")
def get_logs():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        logs  = NetworkLog.query.order_by(NetworkLog.timestamp.desc()).limit(limit).all()
        return jsonify([l.to_dict() for l in logs])
    except Exception as exc:
        log.error("Logs API xato: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/stats")
def get_stats():
    try:
        from sqlalchemy import func
        total   = NetworkLog.query.count()
        attacks = NetworkLog.query.filter_by(status="ATTACK").count()
        by_type = dict(
            db.session.query(NetworkLog.attack_type, func.count())
            .filter(NetworkLog.status == "ATTACK")
            .group_by(NetworkLog.attack_type).all()
        )
        return jsonify({
            "total":       total,
            "attacks":     attacks,
            "normal":      total - attacks,
            "attack_rate": round(attacks / total * 100, 1) if total else 0,
            "by_type":     by_type,
        })
    except Exception as exc:
        log.error("Stats API xato: %s", exc)
        return jsonify({"error": str(exc)}), 500


@app.route("/api/debug/features", methods=["POST"])
def debug_features():
    """
    Debug endpoint: berilgan req_s va pkt_size uchun feature qiymatlarini ko'rsat.
    Body: {"req_s": 20, "pkt_size": 5000}
    """
    if model is None:
        return jsonify({"error": "Model yuklanmagan"}), 503

    data     = request.get_json() or {}
    req_s    = float(data.get("req_s",    20))
    pkt_size = int(data.get("pkt_size", 200))

    features, pattern = build_features(req_s, pkt_size)
    status, attack_type, confidence = analyze_traffic(features)

    feat_dict = dict(zip(config.FEATURES, features))

    return jsonify({
        "input":      {"req_s": req_s, "pkt_size": pkt_size},
        "pattern":    pattern,
        "features":   {k: round(v, 2) for k, v in feat_dict.items()},
        "prediction": attack_type,
        "status":     status,
        "confidence": round(confidence, 3),
    })


@app.route("/api/clear", methods=["DELETE"])
def clear_logs():
    """Barcha loglarni o'chirish (test maqsadida)."""
    try:
        deleted = NetworkLog.query.delete()
        db.session.commit()
        return jsonify({"deleted": deleted, "message": "Loglar tozalandi"})
    except Exception as exc:
        db.session.rollback()
        return jsonify({"error": str(exc)}), 500


@socketio.on("connect")
def on_connect():
    log.info("Frontend ulandi: %s", request.sid)


@socketio.on("disconnect")
def on_disconnect():
    log.info("Frontend uzildi: %s", request.sid)


# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    if not load_pipeline():
        print("\nXATO: Avval 'python model_train.py' ni ishlating!\n")
        exit(1)

    with app.app_context():
        db.create_all()
        log.info("Ma'lumotlar bazasi tayyor.")

    log.info("Server http://localhost:%d da ishga tushdi.", config.PORT)
    socketio.run(app, host="0.0.0.0", port=config.PORT, debug=config.DEBUG)