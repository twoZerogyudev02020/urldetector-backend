from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from pydantic import BaseModel
from urllib.parse import quote, urlparse

import os, json, re, datetime, unicodedata, csv, traceback, time
import requests

import urllib.request
import shutil


import torch
import torch.nn.functional as F
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification

# ===== Google Drive model download (Render-safe) =====
GOOGLE_DRIVE_FILE_ID = os.getenv("GOOGLE_DRIVE_FILE_ID", "").strip()  # "1WmK0Z0trB4Am0bUIiwyvbCTABriEqsf5" 같은 'id'만

def download_from_gdrive(file_id: str, dst_path: str):
    import gdown, os
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)

    # gdown은 confirm/토큰/대용량 다운로드를 안정적으로 처리함
    url = f"https://drive.google.com/uc?id={file_id}"
    out = gdown.download(url, dst_path, quiet=False, fuzzy=True)

    if not out or not os.path.exists(dst_path):
        raise RuntimeError("gdown download failed")

    # HTML 잘못 저장됐는지 1차 검증
    with open(dst_path, "rb") as f:
        head = f.read(16)
    if head.startswith(b"<"):
        # HTML이면 잘못 받은 것 -> 파일 삭제하고 에러
        try:
            os.remove(dst_path)
        except:
            pass
        raise RuntimeError("Downloaded file is HTML (Google Drive permission/confirm issue).")


# =========================
# App
# =========================
app = FastAPI(title="URLDETECTOR API", version="1.2")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 개발용
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================
# ✅ KPI cache (fast)
# =========================
KPI_TTL_SEC = int(os.getenv("KPI_TTL_SEC", "300"))  # 5분 캐시
_kpi_cache = {"ts": 0.0, "data": None}

# =========================
# Paths / Settings
# =========================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PWA_DIR = os.path.join(BASE_DIR, "pwa")  # pwa 경로 상수 추가
# .../URLDETECTOR/backend
MODEL_PATH = os.path.join(BASE_DIR, "distilbert_best.pt")


# ✅ known DB
KNOWN_CSV_PATH = os.path.join(BASE_DIR, "data", "malicious_phish.csv")

# ✅ (Render용) known CSV가 GitHub에 없을 때, 시작 시 외부에서 자동 다운로드
KNOWN_CSV_URL = os.getenv("KNOWN_CSV_URL", "").strip()  # 예: 구글드라이브 direct download 링크
KNOWN_CSV_REQUIRED = os.getenv("KNOWN_CSV_REQUIRED", "1").strip()  # 1이면 없을 때 에러, 0이면 mock만

def ensure_known_csv():
    """
    - KNOWN_CSV_PATH가 없으면 KNOWN_CSV_URL에서 다운로드
    - GitHub Push Protection 회피용 (CSV를 repo에 커밋하지 않음)
    """
    os.makedirs(os.path.dirname(KNOWN_CSV_PATH), exist_ok=True)

    if os.path.exists(KNOWN_CSV_PATH) and os.path.getsize(KNOWN_CSV_PATH) > 1024:
        return True  # 이미 있음

    if not KNOWN_CSV_URL:
        if KNOWN_CSV_REQUIRED == "1":
            raise RuntimeError("KNOWN_CSV_URL이 비어있고, KNOWN_CSV_PATH도 없습니다.")
        print("⚠️ KNOWN_CSV_URL 없음 → known CSV 없이(mock만) 진행")
        return False

    tmp_path = KNOWN_CSV_PATH + ".tmp"
    try:
        print(f"⬇️ Downloading known CSV...\n  from: {KNOWN_CSV_URL}\n  to  : {KNOWN_CSV_PATH}")
        with urllib.request.urlopen(KNOWN_CSV_URL, timeout=60) as r, open(tmp_path, "wb") as f:
            shutil.copyfileobj(r, f)
        if os.path.getsize(tmp_path) < 1024:
            raise RuntimeError("다운로드 파일 크기가 너무 작습니다(실패로 간주).")
        os.replace(tmp_path, KNOWN_CSV_PATH)
        print(f"✅ Known CSV downloaded: {KNOWN_CSV_PATH} ({os.path.getsize(KNOWN_CSV_PATH):,} bytes)")
        return True
    except Exception as e:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except:
            pass
        if KNOWN_CSV_REQUIRED == "1":
            raise
        print(f"⚠️ Known CSV download failed → mock만 진행: {e}")
        return False


# ✅ report log
REPORT_LOG_PATH = os.path.join(BASE_DIR, "data", "reports.jsonl")

LABELS = {0: "SAFE", 1: "DEFACEMENT", 2: "PHISHING", 3: "MALWARE"}

# =========================
# Utils
# =========================
def normalize_text(s: str) -> str:
    s = (s or "").strip()
    return unicodedata.normalize("NFKC", s)

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")

def normalize_url(u: str) -> str:
    """
    - CSV(known)와 브라우저 입력을 매칭시키기 위해 scheme을 통일
    - scheme 없으면 http:// 붙임
    """
    u = normalize_text(u)
    if not u:
        return ""

    u = re.sub(r"\s+", "", u)

    if u.startswith("www."):
        u = "http://" + u

    if not _SCHEME_RE.match(u):
        u = "http://" + u

    return u

def now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def clamp01(x) -> float:
    try:
        x = float(x)
    except:
        return 0.0
    return max(0.0, min(1.0, x))

def safe_int(v, default=0):
    try:
        return int(v)
    except:
        return default

# URL extract (text analyze)
URL_RE = re.compile(r"https?://[^\s<>'\"()]+", re.I)

# =========================
# Known dataset / reported_set
# =========================
known_map: dict[str, str] = {}   # normalized_url -> label
known_host_index: dict[str, list[tuple[str, str]]] = {}  # host -> [(url,label), ...]
reported_set: set[str] = set()

known_load_state = {
    "exists": False,
    "size_bytes": None,
    "first_line": None,
    "fieldnames": None,
    "total_rows": 0,
    "kept_rows": 0,
    "error": None,
    "loaded_at": None,
}

def _host_of(url: str) -> str:
    try:
        return (urlparse(url).netloc or "").lower()
    except:
        return ""

def build_known_index(max_per_host: int = 120):
    global known_host_index
    known_host_index = {}
    for u, lab in known_map.items():
        h = _host_of(u)
        if not h:
            continue
        bucket = known_host_index.get(h)
        if bucket is None:
            known_host_index[h] = [(u, lab)]
        else:
            if len(bucket) < max_per_host:
                bucket.append((u, lab))

def load_known_dataset():
    global known_map, known_load_state

    known_map = {}
    known_load_state = {
        "exists": os.path.exists(KNOWN_CSV_PATH),
        "size_bytes": os.path.getsize(KNOWN_CSV_PATH) if os.path.exists(KNOWN_CSV_PATH) else None,
        "first_line": None,
        "fieldnames": None,
        "total_rows": 0,
        "kept_rows": 0,
        "error": None,
        "loaded_at": None,
    }

    total = 0
    kept = 0

    def pick_col(cols, candidates):
        cols_low = {c.lower(): c for c in cols}
        for cand in candidates:
            if cand.lower() in cols_low:
                return cols_low[cand.lower()]
        return None

    if os.path.exists(KNOWN_CSV_PATH):
        try:
            with open(KNOWN_CSV_PATH, "r", encoding="utf-8", errors="ignore", newline="") as f:
                head = f.readline()
                known_load_state["first_line"] = head[:220]
                f.seek(0)

                sample = f.read(4096)
                f.seek(0)
                try:
                    dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t"])
                except:
                    dialect = csv.excel

                reader = csv.DictReader(f, dialect=dialect)
                known_load_state["fieldnames"] = reader.fieldnames

                if not reader.fieldnames:
                    raise RuntimeError("CSV header(fieldnames)가 비어있습니다.")

                url_col = pick_col(reader.fieldnames, ["url", "URL", "link", "uri"])
                type_col = pick_col(reader.fieldnames, ["type", "label", "category", "class", "result"])

                if not url_col or not type_col:
                    raise RuntimeError(f"CSV 컬럼을 찾지 못했습니다. fieldnames={reader.fieldnames}")

                for row in reader:
                    total += 1
                    raw_url = row.get(url_col, "")
                    raw_type = row.get(type_col, "")

                    u = normalize_url(raw_url)
                    t = normalize_text(raw_type).upper()

                    if not u:
                        continue

                    if t in ["BENIGN", "SAFE", "GOOD", "0"]:
                        label = "SAFE"
                    elif "DEFACE" in t or t in ["DEFACEMENT", "1"]:
                        label = "DEFACEMENT"
                    elif "PHISH" in t or t in ["PHISHING", "2"]:
                        label = "PHISHING"
                    elif "MAL" in t or t in ["MALWARE", "3"]:
                        label = "MALWARE"
                    else:
                        continue

                    known_map[u] = label
                    kept += 1

        except Exception as e:
            known_load_state["error"] = repr(e)
            traceback.print_exc()

    # ✅ mock 3개는 항상 유지
    known_map["http://mock_deface.test/coupon/confirm"] = "DEFACEMENT"
    known_map["http://mock_phish.test/login/verify"] = "PHISHING"
    known_map["http://mock_malware.test/app.apk"] = "MALWARE"

    known_load_state["total_rows"] = total
    known_load_state["kept_rows"] = kept
    known_load_state["loaded_at"] = now_iso()

    build_known_index()

    print(f"✅ KNOWN_CSV_PATH: {KNOWN_CSV_PATH}")
    print(f"✅ known loaded: total_rows={total:,}, kept={kept:,}, known_map={len(known_map):,} (+mock 3)")
    if known_load_state["error"]:
        print("❌ known_load_state.error =", known_load_state["error"])
    else:
        print("✅ known_load_state.fieldnames =", known_load_state["fieldnames"])

def load_reported_set():
    global reported_set
    reported_set = set()
    if os.path.exists(REPORT_LOG_PATH):
        try:
            with open(REPORT_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    try:
                        o = json.loads(line)
                    except:
                        continue
                    u = normalize_url(o.get("url", ""))
                    if u:
                        reported_set.add(u)
        except Exception as e:
            print(f"⚠️ load_reported_set failed: {e}")

# =========================
# Risk scoring (서버 기준)
# =========================
IOC_RE = re.compile(
    r"(@|%40)|(\bverify\b)|(\blogin\b)|(\baccount\b)|(\bupdate\b)|(\bsecure\b)|(\bpay\b)|(\bwallet\b)|(\brefund\b)|(\bconfirm\b)|(\bpassword\b)|(\bbank\b)|(\bcard\b)|(\bpin\b)",
    re.IGNORECASE
)
SHORTENER_RE = re.compile(r"(bit\.ly|t\.co|tinyurl\.com|goo\.gl|is\.gd|cutt\.ly)", re.IGNORECASE)

IOC_KEYWORDS = [
    "login","signin","verify","account","secure","update","otp","auth","password"
]
IOC_FILE_EXT = [
    ".apk",".exe",".msi",".dmg",".zip",".rar",".bat",".scr"
]

def _ioc_score_from_url(url_norm: str) -> int:
    s = (url_norm or "").lower()
    score = 0

    if any(k in s for k in IOC_KEYWORDS):
        score += 10
    if any(ext in s for ext in IOC_FILE_EXT):
        score += 14
    if "xn--" in s:
        score += 10
    if ("%2f" in s) or ("%3a" in s) or ("%2e" in s):
        score += 6

    digits = len(re.findall(r"\d", s))
    specials = len(re.findall(r"[-_@=:]", s))
    if digits >= 8:
        score += 6
    if specials >= 6:
        score += 4

    # host 기반 휴리스틱
    try:
        host = re.sub(r"^https?://", "", s).split("/")[0]
        sub_cnt = host.count(".")
        if len(host) >= 28:
            score += 4
        if sub_cnt >= 3:
            score += 4
    except:
        pass

    return max(0, min(40, int(score)))

def compute_risk_score(label: str, conf01: float, known_match: bool, url_norm: str):
    """
    ✅ 예전(분산형) 공식으로 원복:
    risk = base*0.55 + conf_pct*0.25 + ioc(0~40)*0.50 (+ known +10)
    """
    label = (label or "SAFE").upper()
    conf01 = clamp01(conf01)

    base_map = {"SAFE": 5, "DEFACEMENT": 45, "PHISHING": 65, "MALWARE": 80}
    base = int(base_map.get(label, 5))

    ioc = _ioc_score_from_url(url_norm)  # 0~40
    conf_pct = int(round(conf01 * 100))

    risk = int(round(base * 0.55 + conf_pct * 0.25 + ioc * 0.50))
    if known_match:
        risk = min(risk + 10, 100)
    risk = max(0, min(risk, 100))

    breakdown = {
        "base": base,
        "ioc": int(ioc),
        "conf_pct": conf_pct,
        "known_bonus": 10 if known_match else 0,
        "known_match": bool(known_match),
    }
    return risk, breakdown


def compute_kpi_snapshot():
    total = len(known_map)

    cnt = {"SAFE": 0, "PHISHING": 0, "MALWARE": 0, "DEFACEMENT": 0}
    ioc_short = 0
    ioc_login = 0
    ioc_ip    = 0

    for u, lab in known_map.items():
        lab = (lab or "SAFE").upper()
        if lab not in cnt:
            lab = "SAFE"
        cnt[lab] += 1

        if u:
            if SHORTENER_RE.search(u):
                ioc_short += 1
            if IOC_RE.search(u):
                ioc_login += 1
            if re.search(r"https?://\d{1,3}(\.\d{1,3}){3}", u):
                ioc_ip += 1

    def pct(x):
        return 0.0 if total <= 0 else round((x / total) * 100.0, 2)

    mal_total = cnt["PHISHING"] + cnt["MALWARE"] + cnt["DEFACEMENT"]
    def pct_mal(x):
        return 0.0 if mal_total <= 0 else round((x / mal_total) * 100.0, 2)

    return {
        "known_total": total,
        "known_counts": cnt,
        "known_dist_pct_of_mal": {
            "PHISHING": pct_mal(cnt["PHISHING"]),
            "MALWARE": pct_mal(cnt["MALWARE"]),
            "DEFACEMENT": pct_mal(cnt["DEFACEMENT"]),
        },
        "ioc_ratio_pct": {
            "shortener": pct(ioc_short),
            "login_keywords": pct(ioc_login),
            "ip_link": pct(ioc_ip),
        },
        "generated_at": now_iso(),
    }

# =========================
# Model load (Render-safe)
# =========================

# 구글드라이브 파일 ID (Render 환경변수로도 바꿀 수 있게)
MODEL_FILE_ID = os.getenv("MODEL_FILE_ID", "1WmK0Z0trB4Am0bUIiwyvbCTABriEqsf5")

tokenizer = DistilBertTokenizerFast.from_pretrained("distilbert-base-uncased")
model = DistilBertForSequenceClassification.from_pretrained(
    "distilbert-base-uncased", num_labels=4
)

def download_from_gdrive(file_id: str, dst_path: str):
    """
    Google Drive direct download (큰 파일도 토큰 처리)
    주의: 드라이브 공유가 '링크가 있는 모든 사용자'여야 함.
    """
    import requests
    url = f"https://drive.google.com/uc?export=download&id={file_id}"
    session = requests.Session()
    r = session.get(url, stream=True, allow_redirects=True)

    # 큰 파일이면 확인 토큰(download_warning)이 쿠키로 오는 경우가 있음
    token = None
    for k, v in r.cookies.items():
        if k.startswith("download_warning"):
            token = v
            break

    if token:
        r = session.get(url + f"&confirm={token}", stream=True, allow_redirects=True)

    r.raise_for_status()

    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    with open(dst_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)

def ensure_model_loaded():
    global model

    # 파일이 없으면 다운로드
    if not os.path.exists(MODEL_PATH):
        print(f"⬇️ Model not found. Downloading to {MODEL_PATH} ...")
        download_from_gdrive(MODEL_FILE_ID, MODEL_PATH)
        print("✅ Model download done")

    # 파일이 HTML로 저장된 경우(이전 실패 잔재) 제거 후 재다운
    with open(MODEL_PATH, "rb") as f:
        head = f.read(16)
    if head.startswith(b"<"):
        print("⚠️ Model file looks like HTML. Re-downloading...")
        try:
            os.remove(MODEL_PATH)
        except:
            pass
        download_from_gdrive(MODEL_FILE_ID, MODEL_PATH)
        print("✅ Model re-download done")

    state = torch.load(MODEL_PATH, map_location="cpu")

    if isinstance(state, dict) and "state_dict" in state:
        state = state["state_dict"]

    if isinstance(state, dict):
        model.load_state_dict(state, strict=False)
        print("✅ Model state_dict loaded")
    else:
        model = state
        print("✅ Whole model object loaded")

    model.eval()




# =========================
# ✅ Predict cache
# =========================
PREDICT_CACHE_TTL_SEC = int(os.getenv("PREDICT_CACHE_TTL_SEC", "3600"))
PREDICT_CACHE_MAX = int(os.getenv("PREDICT_CACHE_MAX", "5000"))
_predict_cache: dict[str, tuple[float, dict]] = {}

def _cache_get(url: str):
    rec = _predict_cache.get(url)
    if not rec:
        return None
    ts, val = rec
    if (time.time() - ts) > PREDICT_CACHE_TTL_SEC:
        _predict_cache.pop(url, None)
        return None
    return val

def _cache_set(url: str, val: dict):
    _predict_cache[url] = (time.time(), val)
    if len(_predict_cache) > PREDICT_CACHE_MAX:
        items = sorted(_predict_cache.items(), key=lambda kv: kv[1][0])
        cut = max(1, int(PREDICT_CACHE_MAX * 0.05))
        for k, _ in items[:cut]:
            _predict_cache.pop(k, None)

@app.on_event("startup")
def _startup():

    ensure_model_loaded()

    # ✅ known csv 확보(없으면 다운로드하도록)
    try:
        ensure_known_csv()
    except Exception as e:
        print("[startup] ensure_known_csv failed:", e)

    # ✅ 기타 로컬 데이터 로드 (너 코드에 이미 있으면 유지)
    try:
        load_known_dataset()
    except Exception as e:
        print("[startup] load_known_dataset failed:", e)

    try:
        load_reported_set()
    except Exception as e:
        print("[startup] load_reported_set failed:", e)

    # (선택) 워밍업
    try:
        with torch.no_grad():
            inputs = tokenizer("http://example.com", truncation=True, padding=True, max_length=128, return_tensors="pt")
            _ = model(**inputs)
        print("✅ Warmup done")
    except Exception as e:
        print(f"⚠️ Warmup skipped: {e}")

    # (선택) KPI 캐시
    try:
        _kpi_cache["data"] = compute_kpi_snapshot()
        _kpi_cache["ts"] = time.time()
    except Exception as e:
        print("[startup] KPI snapshot failed:", e)


# =========================
# Schemas
# =========================
class PredictRequest(BaseModel):
    url: str
    risk: int | None = None
    page_url: str | None = None
    anchor_text: str | None = None

class ReportRequest(BaseModel):
    url: str | None = None
    label: str | None = None
    confidence: float | None = None
    page_url: str | None = None
    anchor_text: str | None = None
    user_action: str | None = None
    source: str | None = None

class AnalyzeTextRequest(BaseModel):
    text: str

# =========================
# /
# =========================
@app.get("/")
def root():
    return {
        "ok": True,
        "msg": "URLDETECTOR backend running",
        "endpoints": ["/predict", "/analyze_text", "/report", "/reports", "/guide", "/debug_known", "/kpi"],
        "known_loaded": len(known_map),
        "known_csv_path": KNOWN_CSV_PATH,
        "reports_path": REPORT_LOG_PATH,
        "reported_saved": len(reported_set),
        "known_load_state": known_load_state,
    }

# =========================
# /debug_known
# =========================
@app.get("/debug_known")
def debug_known():
    samples = []
    for i, (u, l) in enumerate(known_map.items()):
        samples.append({"url": u, "label": l})
        if i >= 12:
            break

    return {
        "known_csv_path": KNOWN_CSV_PATH,
        "exists": os.path.exists(KNOWN_CSV_PATH),
        "size_bytes": os.path.getsize(KNOWN_CSV_PATH) if os.path.exists(KNOWN_CSV_PATH) else None,
        "known_loaded": len(known_map),
        "known_load_state": known_load_state,
        "sample": samples,
        "host_index_size": len(known_host_index),
        "some_hosts": list(known_host_index.keys())[:10],
    }

# =========================
# /kpi
# =========================
@app.get("/kpi")
def kpi():
    now = time.time()
    if _kpi_cache["data"] is not None and (now - _kpi_cache["ts"]) < KPI_TTL_SEC:
        return _kpi_cache["data"]

    data = compute_kpi_snapshot()
    _kpi_cache["ts"] = now
    _kpi_cache["data"] = data
    return data

# =========================
# /pwa 접속
# =========================
@app.get("/pwa/manifest.webmanifest")
def pwa_manifest():
    return FileResponse(os.path.join(PWA_DIR, "manifest.webmanifest"),
                        media_type="application/manifest+json")

@app.get("/pwa/sw.js")
def pwa_sw():
    return FileResponse(os.path.join(PWA_DIR, "sw.js"),
                        media_type="application/javascript")

@app.get("/pwa/icon-192.png")
def pwa_icon_192():
    return FileResponse(os.path.join(PWA_DIR, "icon-192.png"),
                        media_type="image/png")

@app.get("/pwa/icon-512.png")
def pwa_icon_512():
    return FileResponse(os.path.join(PWA_DIR, "icon-512.png"),
                        media_type="image/png")

@app.get("/pwa/apple-touch-icon.png")
def pwa_apple_touch_icon():
    return FileResponse(os.path.join(PWA_DIR, "apple-touch-icon.png"),
                        media_type="image/png")

# ✅ app html 경로: backend 폴더의 example_total.html을 우선 사용
APP_HTML_PATH = os.path.join(BASE_DIR, "example_total.html")

@app.get("/app", response_class=HTMLResponse)
def app_page():
    path = os.path.abspath(APP_HTML_PATH)
    if not os.path.exists(path):
        return HTMLResponse(
            content=f"<h2>app html not found</h2><pre>{path}</pre>",
            status_code=404,
        )

    # ✅ 캐시 강제 방지(PC/모바일 모두 최신 HTML 받게)
    return FileResponse(
        path,
        media_type="text/html",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )

# =========================
# /predict
# =========================
@app.post("/predict")
def predict(req: PredictRequest):
    raw_url = req.url or ""
    clean_url = normalize_url(raw_url)

    if not clean_url:
        return {
            "label": "SAFE",
            "confidence": 0.0,
            "known_match": False,
            "known_label": None,
            "risk": 0,
            "risk_breakdown": {
                "base_type": 0, "ioc_signals": 0, "confidence": 0, "known_db_bonus": 0,
                "ioc_raw": 0, "conf_pct": 0, "label_base": 0, "known_match": False
            }
        }

    cached = _cache_get(clean_url)
    if cached is not None:
        out = dict(cached)
        out["original_url"] = raw_url
        out["normalized_url"] = clean_url
        return out

    known_label = known_map.get(clean_url)

    # ✅✅ [핵심] Known이면 모델 추론 스킵
    # ✅ Known이어도 "conf는 모델 확률"로 계산 (label은 Known으로 확정)
    if known_label is not None:
        label = known_label
        pred_idx = {v: k for k, v in LABELS.items()}.get(label, 0)

        # conf만 모델에서 뽑기 (argmax 말고, Known 라벨의 확률)
        inputs = tokenizer(clean_url, truncation=True, padding=True, max_length=128, return_tensors="pt")
        with torch.no_grad():
            outputs = model(**inputs)
            probs = F.softmax(outputs.logits, dim=-1)

        scores = {
            "safe": float(probs[0][0].item()),
            "defacement": float(probs[0][1].item()),
            "phishing": float(probs[0][2].item()),
            "malware": float(probs[0][3].item()),
        }
        
        # ✅ PDF 기준 CONF = max softmax
        conf = max(scores.values())

        # ✅ 모델이 예측한 라벨(참고용)
        pred_idx = int(torch.argmax(probs, dim=-1).item())
        model_label = {0:"SAFE", 1:"DEFACEMENT", 2:"PHISHING", 3:"MALWARE"}[pred_idx]

        # --- risk 결정 로직 수정 ---
        req_risk = safe_int(req.risk, -1)
        known_match = known_label is not None   # ← 이 줄을 먼저 둔다

        if req_risk >= 0:
            risk = req_risk
            risk_breakdown = {"source": "frontend"}
        else:
            risk, risk_breakdown = compute_risk_score(
                label=label,
                conf01=conf,
                known_match=known_match,
                url_norm=clean_url
            )


        out = {
            "original_url": raw_url,
            "normalized_url": clean_url,
            "label": label,
            "class_id": pred_idx,
            "confidence": conf,          # ✅ 이제 0.99 강제 아님
            "scores": scores,
            "is_malicious": (label != "SAFE"),
            "known_match": True,
            "known_label": known_label,
            "risk": risk,
            "risk_breakdown": risk_breakdown,
        }
        _cache_set(clean_url, out)
        return out


# =========================
# /analyze_text
# =========================
@app.post("/analyze_text")
def analyze_text(req: AnalyzeTextRequest):
    text = req.text or ""
    urls = URL_RE.findall(text)
    cleaned = [normalize_url(u) for u in urls if u][:30]
    results = []
    for u in cleaned:
        results.append(predict(PredictRequest(url=u, page_url="pasted_text", anchor_text="pasted_text")))
    return {"urls": cleaned, "results": results}

# =========================
# /report
# =========================
@app.post("/report")
def report(req: ReportRequest, request: Request):
    os.makedirs(os.path.dirname(REPORT_LOG_PATH), exist_ok=True)

    url_raw = req.url or ""
    u = normalize_url(url_raw)
    if not u:
        return JSONResponse({"ok": False, "error": "missing url"}, status_code=400)

    known_label = known_map.get(u)

    # ✅ Known DB면 저장 생략(dedup)
    if known_label is not None:
        return {"ok": True, "deduped": True, "reason": "already_in_known_dataset", "known_label": known_label, "url": u}

    if u in reported_set:
        return {"ok": True, "deduped": True, "reason": "already_reported", "url": u}

    lbl = normalize_text(req.label or "").upper()
    if lbl not in ("SAFE", "DEFACEMENT", "PHISHING", "MALWARE"):
        pred = predict(PredictRequest(url=u))
        lbl = pred.get("label", "SAFE")

    conf = clamp01(req.confidence if req.confidence is not None else 0.0)

    item = {
        "ts": now_iso(),
        "event": "USER_REPORT",
        "url": u,
        "label": lbl,
        "confidence": conf,
        "page_url": req.page_url,
        "anchor_text": req.anchor_text,
        "user_action": req.user_action or "REPORT_CLICK",
        "source": req.source or "extension",
        "user_agent": request.headers.get("user-agent"),
        "known_match": False,
        "known_label": None,
    }

    with open(REPORT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(item, ensure_ascii=False) + "\n")

    reported_set.add(u)
    return {"ok": True, "deduped": False, "saved_to": REPORT_LOG_PATH, "item": item}

# =========================
# /reports (대시보드)  ✅ “Saved in reports” 제거(혼란 방지)
# =========================
@app.get("/reports")
def reports(
    request: Request,
    limit: int = Query(120, ge=1, le=1000),
    format: str = Query("html"),
    url: str = Query(""),
    q: str = Query(""),
):
    highlight = normalize_url(url) if url else ""
    q_norm = normalize_text(q).lower().strip()

    items = []
    if os.path.exists(REPORT_LOG_PATH):
        try:
            with open(REPORT_LOG_PATH, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            for line in reversed(lines):
                try:
                    o = json.loads(line)
                except:
                    continue
                if o.get("event") == "USER_REPORT":
                    items.append(o)
                if len(items) >= limit:
                    break
        except:
            pass

    if (format or "").lower() == "json":
        samples = []
        for i, (ku, kl) in enumerate(known_map.items()):
            samples.append({"url": ku, "label": kl})
            if i >= 19:
                break
        return {
            "highlight_url": highlight or None,
            "q": q_norm or None,
            "known_loaded": len(known_map),
            "highlight_known_match": bool(known_map.get(highlight)) if highlight else False,
            "highlight_known_label": known_map.get(highlight) if highlight else None,
            "known_samples": samples,
            "reports_items": items,
        }

    def esc(s):
        return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    known_label = known_map.get(highlight) if highlight else None
    match_text = "—"
    if highlight:
        match_text = f"YES · {known_label} (malicious_phish.csv)" if known_label else "NO"

    rows_html = ""
    for it in items:
        u = it.get("url", "")
        badge = it.get("label", "SAFE")
        c = int(round(float(it.get("confidence", 0)) * 100))
        ts = it.get("ts", "")
        hl = " hl" if highlight and u == highlight else ""
        rows_html += f"""
          <div class="row{hl}">
            <div class="c1 mono">{esc(u)}</div>
            <div class="c2"><span class="tag {esc(badge)}">{esc(badge)} {c}%</span></div>
            <div class="c3">{esc(ts)}</div>
          </div>
        """

    auto_q = q_norm
    if not auto_q and highlight:
        auto_q = (_host_of(highlight) or "").lower()

    known_hits: list[tuple[str, str]] = []
    pinned = (highlight, known_label) if (highlight and known_label) else None

    if auto_q:
        if auto_q in known_host_index:
            known_hits.extend(known_host_index[auto_q])

        if len(known_hits) < 50:
            for h in known_host_index.keys():
                if auto_q in h:
                    for pair in known_host_index[h]:
                        known_hits.append(pair)
                        if len(known_hits) >= 50:
                            break
                if len(known_hits) >= 50:
                    break

        if pinned:
            known_hits = [(u, l) for (u, l) in known_hits if u != pinned[0]]

    known_rows = ""
    if pinned:
        known_rows += f"""
          <div class="krow pin">
            <div class="k1 mono">{esc(pinned[0])}</div>
            <div class="k2"><span class="tag {esc(pinned[1])}">{esc(pinned[1])}</span></div>
            <div class="k3"><span class="ok">HIGHLIGHT MATCH</span></div>
          </div>
        """

    for (u, l) in known_hits[:50]:
        known_rows += f"""
          <div class="krow">
            <div class="k1 mono">{esc(u)}</div>
            <div class="k2"><span class="tag {esc(l)}">{esc(l)}</span></div>
            <div class="k3"></div>
          </div>
        """

    known_summary = ""
    if auto_q:
        known_summary = f"검색어: <b>{esc(auto_q)}</b> · 결과: <b>{len(known_hits) + (1 if pinned else 0)}</b> / 최대 50"
    else:
        known_summary = "검색어를 입력하면 malicious_phish.csv(known DB)에서 최대 50개까지 보여줍니다."

    reports_link = "/reports"
    if highlight:
        reports_link = "/reports?url=" + quote(highlight, safe=":/?&=%.-_~")

    html = f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<script>
  if ("serviceWorker" in navigator) {{
    window.addEventListener("load", () => {{
      navigator.serviceWorker.register("/pwa/sw.js").catch(() => {{}});
    }});
  }}
</script>

</script>

<title>URLDETECTOR · Reports</title>
<style>
  body{{margin:0;background:#05070d;color:rgba(255,255,255,.92);font-family:system-ui,-apple-system,Malgun Gothic}}
  .wrap{{max-width:1150px;margin:0 auto;padding:26px 18px 44px}}
  .card{{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:22px;padding:18px}}
  .h{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:14px}}
  .title{{font-weight:950;font-size:18px;letter-spacing:.3px}}
  .muted{{color:rgba(255,255,255,.72);margin-top:6px;line-height:1.55}}
  .pill{{display:inline-flex;gap:8px;align-items:center;border:1px solid rgba(255,255,255,.14);border-radius:999px;padding:10px 12px;background:rgba(0,0,0,.30);font-weight:950}}
  .mono{{font-family:ui-monospace,Consolas,monospace}}
  .grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}}
  @media (max-width:900px){{.grid{{grid-template-columns:1fr}}}}
  .panel{{border:1px solid rgba(255,255,255,.12);border-radius:18px;background:rgba(0,0,0,.22);padding:14px}}
  .label{{color:rgba(255,255,255,.62);font-size:12px;font-weight:950;letter-spacing:.4px}}
  .v{{margin-top:8px;font-weight:950}}
  .btns{{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}}
  a{{text-decoration:none}}
  .btn{{border-radius:14px;padding:10px 12px;font-weight:950;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.10);color:rgba(0,0,0,.88)}}
  .btn2{{border-radius:14px;padding:10px 12px;font-weight:950;border:1px solid rgba(255,179,71,.42);background:rgba(255,179,71,.22);color:rgba(0,0,0,.88)}}
  .small{{color:rgba(255,255,255,.62);font-size:12px;line-height:1.5;margin-top:10px}}

  .list{{margin-top:14px}}
  .headRow,.row{{display:grid;grid-template-columns: 1fr 160px 190px;gap:12px;padding:10px 12px;border-radius:14px}}
  .headRow{{background:rgba(0,0,0,.28);border:1px solid rgba(255,255,255,.12);font-weight:950;color:rgba(255,255,255,.84)}}
  .row{{border:1px solid rgba(255,255,255,.10);background:rgba(255,255,255,.06);margin-top:8px}}
  .row.hl{{outline:2px solid rgba(255,179,71,.55);background:rgba(255,179,71,.08)}}

  .kbox{{margin-top:14px;border:1px solid rgba(255,255,255,.12);border-radius:18px;background:rgba(0,0,0,.22);padding:14px}}
  .searchRow{{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:10px}}
  .inp{{flex:1;min-width:220px;border-radius:14px;padding:10px 12px;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.08);color:rgba(255,255,255,.92);font-weight:900}}
  .go{{border-radius:14px;padding:10px 14px;font-weight:950;border:1px solid rgba(120,210,255,.28);background:rgba(120,210,255,.18);color:rgba(0,0,0,.88);cursor:pointer}}
  .khead,.krow{{display:grid;grid-template-columns: 1fr 170px 150px;gap:12px;padding:10px 12px;border-radius:14px}}
  .khead{{margin-top:12px;background:rgba(0,0,0,.28);border:1px solid rgba(255,255,255,.12);font-weight:950;color:rgba(255,255,255,.84)}}
  .krow{{border:1px solid rgba(255,255,255,.10);background:rgba(255,255,255,.06);margin-top:8px}}
  .krow.pin{{outline:2px solid rgba(120,210,255,.40);background:rgba(120,210,255,.08)}}
  .ok{{display:inline-flex;align-items:center;justify-content:center;padding:6px 10px;border-radius:999px;font-weight:950;font-size:12px;background:rgba(120,210,255,.18);border:1px solid rgba(120,210,255,.28);color:rgba(0,0,0,.88)}}

  .tag{{display:inline-block;padding:6px 10px;border-radius:999px;font-weight:950;font-size:12px;border:1px solid rgba(255,255,255,.14)}}
  .PHISHING{{background:rgba(255,77,79,.22);border-color:rgba(255,77,79,.42)}}
  .DEFACEMENT{{background:rgba(255,179,71,.22);border-color:rgba(255,179,71,.42)}}
  .MALWARE{{background:rgba(139,92,246,.22);border-color:rgba(139,92,246,.40)}}
  .SAFE{{background:rgba(255,255,255,.10);border-color:rgba(255,255,255,.16)}}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="h">
      <div>
        <div class="title">URLDETECTOR · 신고 대시보드</div>
        <div class="muted">사용자 신고 로그(reports.jsonl) + Known DB(malicious_phish.csv) 근거를 함께 보여줍니다.</div>
      </div>
      <div class="pill">REPORTS · {len(items)} rows</div>
    </div>

    <div class="grid">
      <div class="panel">
        <div class="label">HIGHLIGHT URL</div>
        <div class="v mono">{esc(highlight) if highlight else "—"}</div>
        <div class="btns">
          <a class="btn" href="{reports_link}">새로고침</a>
          <a class="btn2" href="/reports?format=json" target="_blank" rel="noopener noreferrer">JSON 보기</a>
          <a class="btn" href="/debug_known" target="_blank" rel="noopener noreferrer">debug_known</a>
        </div>
      </div>
      <div class="panel">
        <div class="label">DATASET STATUS</div>
        <div class="v">KNOWN DATASET MATCH: <b>{esc(match_text)}</b></div>
        <div class="v" style="margin-top:6px">REPORT LOG: <b>{len(items)} rows</b></div>
        <div class="small">
          malicious_phish.csv에 존재하는 URL은 /report에서 저장이 생략(deduped)될 수 있습니다.<br/>
          따라서 “저장 여부”보다 MATCH=YES(근거 제시)와 KPI를 중심으로 보시면 됩니다.
        </div>
      </div>
    </div>

    <div class="kbox">
      <div class="label">KNOWN DB (malicious_phish.csv) EVIDENCE</div>
      <div class="v">{known_summary}</div>
      <form class="searchRow" method="get" action="/reports">
        <input type="hidden" name="url" value="{esc(highlight) if highlight else ""}"/>
        <input class="inp" name="q" placeholder="URL/도메인 검색 (예: google, .kr, login, paypal ...)" value="{esc(q_norm)}"/>
        <button class="go" type="submit">검색</button>
      </form>

      <div class="khead">
        <div>KNOWN URL</div><div>LABEL</div><div>HINT</div>
      </div>
      {known_rows if known_rows else '<div class="small" style="margin-top:10px">표시할 결과가 없습니다. 검색어를 입력하거나, highlight URL이 있으면 자동 검색합니다.</div>'}
      <div class="small" style="margin-top:10px">
        Known DB 총 {len(known_map):,}개 로드됨. (성능을 위해 host 인덱스로 최대 50개만 표시)
      </div>
    </div>

    <div class="list">
      <div class="headRow">
        <div>URL</div><div>LABEL</div><div>TIME(UTC)</div>
      </div>
      {rows_html if rows_html else '<div class="small" style="margin-top:10px">저장된 신고가 아직 없습니다.</div>'}
    </div>
  </div>
</div>
</body>
</html>"""

    return HTMLResponse(content=html)

# =========================
# /guide (KPI 시각화 포함)
# =========================
@app.get("/guide", response_class=HTMLResponse)
def guide(url: str = "", label: str = "SAFE", conf: int = 0, risk: int = -1):
    try:
        label = normalize_text(label).upper() or "SAFE"
        url_norm = normalize_url(url)
        conf = max(0, min(safe_int(conf, 0), 100))

        if not url_norm:
            return HTMLResponse(
                content=f"""
                <html><head>
                  <meta http-equiv="refresh" content="0; url=/app" />
                </head>
                <body style="font-family:system-ui;background:#05070d;color:white;padding:24px">
                  <h2>URL이 비어있습니다</h2>
                  <p>앱으로 이동합니다… (<a style="color:#8bdcff" href="/app">/app</a>)</p>
                </body></html>
                """,
                status_code=200
            )


        url_esc = quote(url_norm, safe=":/?&=%.-_~")

        # ✅✅ 핵심: guide는 query로 conf/label을 받지 말고, url만 있으면 서버에서 predict를 돌려서 채운다.
        # (label/conf/risk가 명시로 들어온 경우만 예외적으로 그 값을 사용)
        use_query_override = False

        if not use_query_override:
            pred = predict(PredictRequest(url=url_norm, page_url="guide", anchor_text="guide"))
            label = (pred.get("label") or "SAFE").upper()
            conf = int(round(float(pred.get("confidence", 0.0)) * 100))
            risk_val = int(pred.get("risk", 0))
            rb = pred.get("risk_breakdown") or {}
            known_label = pred.get("known_label")
            known_match = bool(pred.get("known_match", False))
        else:
            # (기존 방식 유지) query로 넘어온 label/conf/risk를 사용
            known_label = known_map.get(url_norm)
            if known_label:
                label = known_label
            known_match = (known_label is not None)

            risk_in = safe_int(risk, -1)
            if risk_in < 0:
                risk_val, rb = compute_risk_score(
                    label=label,
                    conf01=conf / 100.0,
                    known_match=known_match,
                    url_norm=url_norm
                )
            else:
                risk_val = max(0, min(risk_in, 100))
                _, rb = compute_risk_score(
                    label=label,
                    conf01=conf / 100.0,
                    known_match=known_match,
                    url_norm=url_norm
                )

        if not isinstance(rb, dict):
            rb = {}


        match_text = "NO" if not known_label else f"YES · {known_label} (malicious_phish.csv)"
        if risk_val < 40:
            sev = "SAFE"
        elif risk_val < 70:
            sev = "MED"
        elif risk_val < 85:
            sev = "HIGH"
        else:
            sev = "CRITICAL"
            
        fill_color = {
            "SAFE": "rgba(120,210,255,0.70)",     # 파랑
            "MED": "rgba(255,255,0,1.00)",       # 노랑
            "HIGH": "rgba(255,179,71,0.75)",       # 주황
            "CRITICAL": "rgba(255,77,79,0.78)",       # 빨강
        }.get(sev, "rgba(255,255,255,0.30)")



        if known_match:
            brief1 = f"Known DB에 등록된 URL로 확인됨 → {label} (모델 신뢰도 {conf}%)"
        else:
            brief1 = f"모델이 {label}로 분류했고 신뢰도는 {conf}% 입니다."

        # ✅✅✅ [핵심 수정] compute_risk_score() breakdown 키와 /guide 표시 키를 일치시켜서 0으로 안 뜨게 함
        b_base = int(rb.get("base", 0))
        b_ioc  = int(rb.get("ioc", 0))
        b_conf = int(rb.get("conf_pct", 0))
        b_kn   = int(rb.get("known_bonus", 0))

        # 참고: 실제 risk 계산에서 쓰는 가중치(설명용)
        c_base = int(round(b_base * 0.55))
        c_conf = int(round(b_conf * 0.25))
        c_ioc  = int(round(b_ioc  * 0.50))
        c_kn   = int(b_kn)
        approx_sum = c_base + c_conf + c_ioc + c_kn

        brief2 = f"위험도 {risk_val}/100({sev}). Base {b_base} + IOC {b_ioc} + Conf {b_conf} + Known {b_kn}."
        if label in ("PHISHING", "MALWARE"):
            brief3 = "지금은 접속/설치/로그인을 하지 말고, 공식 채널로 직접 확인 후 신고하세요."
        elif label == "DEFACEMENT":
            brief3 = "변조 가능성이 있으니 링크를 즉시 열지 말고, 도메인/공지 출처를 재확인하세요."
        else:
            brief3 = "의심 정황이 있으면 신고 후, 공식 채널에서 동일 내용을 교차 확인하세요."

        advice_map = {
            "DEFACEMENT": [
                "출처(발신번호/기관) 확인 후 공식 채널에서 동일 공지 여부 확인",
                "이벤트·쿠폰·결제 유도 문구가 있으면 공식 앱/홈페이지에서 직접 확인",
                "링크 접속 전, 브라우저 주소(도메인) 일치 여부를 재확인"
            ],
            "PHISHING": [
                "아이디/비밀번호/인증번호 입력을 절대 하지 마세요",
                "기관은 링크 클릭으로 로그인/본인인증을 강요하지 않습니다",
                "이미 입력했다면 즉시 비밀번호 변경 및 2단계 인증(2FA) 점검"
            ],
            "MALWARE": [
                "APK/EXE 등 설치 파일 다운로드·실행을 절대 하지 마세요",
                "다운로드 기록/최근 설치 앱을 확인하고 보안 검사 실행",
                "감염 의심 시 네트워크 차단 후 기기 점검(백신/전문가 도움)"
            ],
            "SAFE": [
                "정상 가능성이 높지만, 출처 불명 메시지는 항상 주의하세요",
                "공식 사이트/앱에서 동일 내용을 직접 확인하는 습관이 안전합니다",
                "의심 정황이 있으면 신고 후 담당자 안내를 따르세요"
            ]
        }
        tips = "".join([f"<li>{x}</li>" for x in advice_map.get(label, advice_map["SAFE"])])

        reports_link = "/reports?url=" + quote(url_norm, safe=":/?&=%.-_~")

        html = f"""<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<script>
  if ("serviceWorker" in navigator) {{
    window.addEventListener("load", () => {{
      navigator.serviceWorker.register("/pwa/sw.js").catch(() => {{}});
    }});
  }}
</script>

<title>URLDETECTOR · 안내 페이지</title>
<style>
  body{{margin:0;background:#05070d;color:rgba(255,255,255,.92);font-family:system-ui,-apple-system,Malgun Gothic}}
  .wrap{{max-width:980px;margin:0 auto;padding:26px 18px}}
  .card{{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.12);border-radius:22px;padding:18px}}
  .h{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:14px}}
  .title{{font-weight:950;font-size:20px;letter-spacing:.3px}}
  .muted{{color:rgba(255,255,255,.72);margin-top:6px;line-height:1.55}}
  .pill{{display:inline-flex;gap:10px;align-items:center;border:1px solid rgba(255,255,255,.14);border-radius:999px;padding:10px 12px;background:rgba(0,0,0,.30);font-weight:950}}
  .panel{{border:1px solid rgba(255,255,255,.12);border-radius:18px;background:rgba(0,0,0,.22);padding:14px;margin-top:12px}}
  .label{{color:rgba(255,255,255,.62);font-size:12px;font-weight:950;letter-spacing:.4px}}
  .mono{{font-family:ui-monospace,Consolas,monospace}}

  /* RISK BAR */
  .barWrap{{position:relative;margin-top:10px}}
  .bar{{
    height:12px;border-radius:999px;
    background:
    repeating-linear-gradient(
      90deg,
      rgba(255,255,255,.14) 0px,
      rgba(255,255,255,.14) 1px,
      rgba(0,0,0,0) 1px,
      rgba(0,0,0,0) 10%
    ),
    rgba(255,255,255,.10);
  overflow:hidden;
  border:1px solid rgba(255,255,255,.14);
    }}
  .fill{{height:100%;width:{risk_val}%;background:linear-gradient(90deg, rgba(120,210,255,.55), rgba(255,179,71,.65), rgba(255,77,79,.72))}}

  /* ✅✅✅ (4-a) 구간 마커: 40/70/85 */
  .mark{{position:absolute;top:-3px;bottom:-3px;width:1px;background:rgba(255,255,255,0.42);pointer-events:none}}
  .m40{{left:40%}}
  .m70{{left:70%}}
  .m85{{left:85%}}
  .bandRow{{position:relative;height:16px;margin-top:8px;font-size:12px;font-weight:900;color:rgba(255,255,255,.62)}}
  .bandRow .b{{position:absolute;top:0;transform:translateX(-50%);white-space:nowrap;opacity:.95}}
  .bandRow .b0{{left:0%;transform:translateX(0)}}
  .bandRow .b40{{left:40%}}
  .bandRow .b70{{left:70%}}
  .bandRow .b85{{left:85%}}
  .bandRow .b100{{left:100%;transform:translateX(-100%)}}


  .explain{{margin-top:10px;color:rgba(255,255,255,.72);line-height:1.55;font-weight:900}}
  .smallBox{{margin-top:10px;border:1px solid rgba(255,255,255,.12);border-radius:14px;background:rgba(255,255,255,.06);padding:10px 12px}}

  .btnRow{{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;align-items:center;justify-content:space-between}}
  .btns{{display:flex;gap:10px;flex-wrap:wrap}}
  button{{cursor:pointer}}
  .b1{{border-radius:14px;padding:12px 14px;font-weight:950;border:1px solid rgba(255,77,79,.40);background:rgba(255,77,79,.22);color:rgba(255,255,255,.92)}}
  .b2{{border-radius:14px;padding:12px 14px;font-weight:950;border:1px solid rgba(255,179,71,.42);background:rgba(255,179,71,.22);color:rgba(255,255,255,.92)}}
  .b3{{border-radius:14px;padding:12px 14px;font-weight:950;border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.10);color:rgba(255,255,255,.92)}}
  a{{text-decoration:none}}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="h">
      <div>
        <div class="title">URLDETECTOR · 안내 페이지</div>
        <div class="muted">원본 사이트로 바로 이동하지 않고, 먼저 위험 유형과 주의사항을 안내합니다.</div>
      </div>
    </div>

    <div class="panel">
      <div class="label">THREAT BRIEF</div>
      <div style="margin-top:8px;font-weight:950;line-height:1.6">{brief1}<br/>{brief2}<br/>{brief3}</div>
    </div>

    <div class="panel">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px">
        <div class="label">RISK SCORE</div>
        <div style="font-weight:950">{risk_val}/100</div>
      </div>

      <div class="barWrap">
        <div class="bar"><div class="fill"></div></div>
        <div class="mark m40"></div>
        <div class="mark m70"></div>
        <div class="mark m85"></div>
      </div>

      <div class="bandRow">
        <span class="b b0">SAFE (0–39)</span>
        <span class="b b40">MED (40–69)</span>
        <span class="b b70">HIGH (70–84)</span>
        <span class="b b85">CRITICAL (85–100)</span>
        <span class="b b100"></span>
      </div>


      <div style="margin-top:10px;color:rgba(255,255,255,.86);font-weight:950">
        Breakdown · Base({b_base}) + IOC({b_ioc}) + Conf({b_conf}) + Known({b_kn})
      </div>

      <div class="smallBox">
        <div class="label">점수 해석</div>
        <div class="explain">
          • <b>Conf(신뢰도)</b>: AI가 “이 유형({label})이 맞다”고 확신하는 정도(0~100).<br/>
          • <b>Risk(위험도)</b>: 실제 사용자 보호를 위해 <b>유형 + URL 신호(IOC) + Known DB</b>를 합쳐 “조심해야 할 정도”를 0~100으로 산출합니다.
        </div>
        <div class="explain" style="margin-top:8px">
          구성요소 의미: <b>Base</b>=유형 자체 기본 위험도, <b>IOC</b>=URL에 포함된 의심 신호(로그인/설치/단축URL 등),
          <b>Conf</b>=신뢰도, <b>Known</b>=Known DB 일치 보너스.
        </div>
        <div class="explain" style="margin-top:8px">
          (설명용 근사치) Base≈{c_base} + IOC≈{c_ioc} + Conf≈{c_conf} + Known={c_kn} → 합≈{approx_sum}
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="label">SUSPICIOUS URL</div>
      <div class="mono" style="margin-top:8px;font-weight:950;word-break:break-all">{url_norm}</div>
      <div class="label" style="margin-top:14px">KNOWN DATASET MATCH</div>
      <div style="margin-top:8px;font-weight:950">{match_text}</div>
    </div>

    <div class="panel" id="kpiBox">
      <div class="label">KPI (Known DB 기반)</div>
      <div style="margin-top:8px;color:rgba(255,255,255,.72);font-weight:900">불러오는 중…</div>
    </div>

    <div class="panel">
      <div class="label">주의해야 할 점</div>
      <ul style="margin:10px 0 0 18px;color:rgba(255,255,255,.86);line-height:1.65;font-weight:900">
        {tips}
      </ul>
    </div>

    <div class="btnRow">
      <div class="btns">
        <button class="b1" onclick="report()">🚨 신고 접수</button>
        <button class="b2" onclick="go()">⚠ 그래도 열기</button>
        <button class="b3" onclick="window.close()">닫기</button>
      </div>
      <a class="b3" href="{reports_link}" target="_blank" rel="noopener noreferrer">📊 신고 대시보드</a>
    </div>
  </div>
</div>

<script>
function go() {{
  const u = "{url_esc}";
  const ok = confirm("위험 사이트로 이동하시겠습니까?\\n\\n" + u);
  if(ok) window.location.href = u;
}}
async function report() {{
  try {{
    const res = await fetch("/report", {{
      method: "POST",
      headers: {{ "Content-Type": "application/json" }},
      body: JSON.stringify({{
        url: "{url_esc}",
        label: "{label}",
        confidence: {conf}/100.0,
        page_url: document.referrer || "",
        anchor_text: "guide_page",
        user_action: "GUIDE_REPORT",
        source: "guide"
      }})
    }});
    const j = await res.json();
    alert("신고 처리: " + (j.deduped ? "중복/DB등록됨" : "저장 완료"));
  }} catch(e) {{
    alert("신고 실패(네트워크/서버 확인)");
  }}
}}

async function loadKPI() {{
  try {{
    const r = await fetch("/kpi");
    const k = await r.json();
    const el = document.getElementById("kpiBox");
    if(!el) return;

    const dist = k.known_dist_pct_of_mal || {{}};
    const ioc  = k.ioc_ratio_pct || {{}};

    const ph = Number(dist.PHISHING ?? 0);
    const ma = Number(dist.MALWARE ?? 0);
    const de = Number(dist.DEFACEMENT ?? 0);

    function barRow(name, v) {{
      const val = Number(v||0);
      const w = Math.max(0, Math.min(100, val));
      return `
        <div style="display:grid;grid-template-columns:110px 1fr 60px;gap:10px;align-items:center;margin-top:8px">
          <div style="color:rgba(255,255,255,.75);font-weight:900">${{name}}</div>
          <div style="height:10px;border-radius:999px;background:rgba(255,255,255,.10);border:1px solid rgba(255,255,255,.12);overflow:hidden">
            <div style="height:100%;width:${{w}}%;background:rgba(120,210,255,.55)"></div>
          </div>
          <div style="text-align:right;font-weight:950">${{val.toFixed(2)}}%</div>
        </div>
      `;
    }}

    const a1 = ph;
    const a2 = ph + ma;

    el.innerHTML = `
      <div class="label">KPI (Known DB 기반)</div>
      <div style="margin-top:10px;display:grid;grid-template-columns:140px 1fr;gap:14px;align-items:center">
        <div style="
          width:128px;height:128px;border-radius:999px;
          background: conic-gradient(
            rgba(255,77,79,.85) 0% ${{a1}}%,
            rgba(139,92,246,.80) ${{a1}}% ${{a2}}%,
            rgba(255,179,71,.85) ${{a2}}% 100%
          );
          border:1px solid rgba(255,255,255,.12);
          position:relative;
        ">
          <div style="
            position:absolute;inset:18px;border-radius:999px;
            background:#05070d;border:1px solid rgba(255,255,255,.10);
            display:flex;align-items:center;justify-content:center;
            text-align:center;font-weight:950;
          ">
            <div>
              <div style="font-size:12px;color:rgba(255,255,255,.65)">Known DB</div>
              <div style="margin-top:2px">${{(k.known_total||0).toLocaleString()}} URLs</div>
            </div>
          </div>
        </div>

        <div>
          <div style="font-weight:950;margin-bottom:8px">Known 유형 분포(악성 내)</div>
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px;font-weight:900">
            <span>PHISH ${{ph.toFixed(2)}}%</span>
            <span>· MAL ${{ma.toFixed(2)}}%</span>
            <span>· DEF ${{de.toFixed(2)}}%</span>
          </div>

          <div style="font-weight:950;margin-bottom:8px">IOC 신호 비율(known 전체)</div>
          ${{barRow("shortener", ioc.shortener)}}
          ${{barRow("login키워드", ioc.login_keywords)}}
          ${{barRow("IP-link", ioc.ip_link)}}
        </div>
      </div>
    `;
  }} catch(e) {{}}
}}
loadKPI();
</script>
</body>
</html>"""
        return HTMLResponse(content=html)

    except Exception as e:
        traceback.print_exc()
        return HTMLResponse(
            content=f"<html><body style='font-family:system-ui;background:#05070d;color:white;padding:24px'><h2>Guide error</h2><pre>{e}</pre></body></html>",
            status_code=200
        )
