from flask import Flask, request, render_template, send_file, jsonify, session, redirect, url_for
from PIL import Image, ImageOps
from io import BytesIO
import os
import requests
import cloudinary
import cloudinary.uploader
import cloudinary.api
from concurrent.futures import ThreadPoolExecutor
import time
from datetime import datetime, timezone
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
import hashlib
import re
import logging
from supabase import create_client, Client
import time

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

from tokens import ACCESS_TOKENS

# ---- Security Logging (stdout only for Serverless) ----
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.WARNING)
# On Vercel, logs from StreamHandler (stdout/stderr) are automatically captured
security_logger.addHandler(logging.StreamHandler())

def log_security_event(event_type, details):
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', 'unknown')
    msg = f"[{event_type}] IP: {ip} | UA: {ua} | Details: {details}"
    security_logger.warning(msg)

def get_session_fingerprint():
    """Create a hash of mostly IP prefix to bind the session, with UA as optional salt."""
    # Relaxed fingerprinting: UA can sometimes change in embedded browsers/webviews.
    # We'll use the IP prefix and a simplified UA check if possible.
    ip_parts = str(request.remote_addr).split('.')
    ip_prefix = ".".join(ip_parts[:2]) if len(ip_parts) >= 2 else "unknown"
    fingerprint_raw = f"{ip_prefix}" # Only bind to IP prefix for maximum compatibility
    return hashlib.sha256(fingerprint_raw.encode()).hexdigest()

# Configuration from environment variables
REMOVE_BG_API_KEY = os.getenv("REMOVE_BG_API_KEY")
CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Strict check for required production keys
if not all([REMOVE_BG_API_KEY, CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET]):
    logger.error("Missing critical environment variables (REMOVE_BG_API_KEY or Cloudinary config)")

if not FLASK_SECRET_KEY:
    logger.warning("FLASK_SECRET_KEY not set. Using a fallback, but this is insecure for production.")
    FLASK_SECRET_KEY = "insecure-fallback-key"

# ---- Token Persistence (Supabase) ----
supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        logger.error(f"Failed to initialize Supabase: {e}")

def token_valid(token: str) -> bool:
    if token == "SNAP-DEV-TEST":
        return True
    if not token or token not in ACCESS_TOKENS:
        return False

    # Check if used in database
    if supabase:
        try:
            result = supabase.table("used_tokens").select("token").eq("token", token).execute()
            if result.data:
                return False
        except Exception as e:
            logger.error(f"Database error during token validation: {e}")
            # Fail closed for security
            return False
            
    expiry = ACCESS_TOKENS[token]
    if expiry is None:
        return True
    return datetime.now(timezone.utc) < expiry

def consume_token(token: str):
    """Mark token as used. SNAP-DEV-TEST is exempt."""
    if token == "SNAP-DEV-TEST":
        return
    if token in ACCESS_TOKENS:
        if supabase:
            try:
                supabase.table("used_tokens").insert({"token": token}).execute()
            except Exception as e:
                logger.error(f"Failed to consume token in database: {e}")

# ---- Smart Enhancement Presets ----
ENHANCE_PRESETS = {
    "dark": [
        # Aggressive brightening for underexposed / low-light shots
        {"effect": "auto_color"},
        {"effect": "auto_brightness"},
        {"effect": "brightness:22"},
        {"effect": "gamma:-22"},
        {"effect": "fill_light:30"},
        {"effect": "contrast:12"},
        {"effect": "sharpen:65"},
    ],
    "warm": [
        # Cool down yellow/orange cast, restore neutral skin tones
        {"effect": "auto_color"},
        {"effect": "improve:50"},
        {"effect": "saturation:-10"},
        {"effect": "brightness:10"},
        {"effect": "fill_light:15"},
        {"effect": "contrast:8"},
        {"effect": "sharpen:55"},
    ],
    "normal": [
        # Balanced natural enhancement for well-lit photos
        {"effect": "auto_color"},
        {"effect": "auto_brightness"},
        {"effect": "improve:50"},
        {"effect": "brightness:12"},
        {"effect": "gamma:-12"},
        {"effect": "fill_light:20"},
        {"effect": "contrast:10"},
        {"effect": "sharpen:45"},
    ],
}

# ---- Rate Limiting ----
limiter = Limiter(
    get_remote_address,
    app=None,
    default_limits=["200 per day", "100 per hour"],
    storage_uri="memory://",
)

app = Flask(__name__, static_folder='assets', static_url_path='/assets')
app.secret_key = FLASK_SECRET_KEY
csrf = CSRFProtect(app)

# Initialize limiter with app
limiter.init_app(app)

# Cloudinary Configuration
cloudinary.config(
  cloud_name = CLOUDINARY_CLOUD_NAME,
  api_key = CLOUDINARY_API_KEY,
  api_secret = CLOUDINARY_API_SECRET,
  secure = True
)

@app.after_request
def add_security_headers(response):
    """Add basic security headers to every response."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"ok": False, "error": "Endpoint not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal Server Error: {error}")
    return jsonify({"ok": False, "error": "Internal server error. Please try again later."}), 500


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"ok": False, "error": "Too many requests. Please slow down."}), 429

@app.route("/")
def index():
    # Allow unlocking via URL parameter (e.g. /?token=SNAP-XXX)
    token_param = request.args.get("token", "").strip().upper()
    if token_param and token_valid(token_param):
        consume_token(token_param)
        session["authenticated"] = True
        session["fingerprint"] = get_session_fingerprint()
        log_security_event("TOKEN_VALIDATED_URL", f"Token: {token_param}")
        return redirect(url_for("index"))

    authenticated = session.get("authenticated", False)
    return render_template("index.html", authenticated=authenticated)

@app.route("/validate-token", methods=["POST"])
@limiter.limit("5 per minute")
def validate_token():
    # 1. Honeypot check (anti-bot)
    # We use request.form because simple bots fill form fields in a POST
    # even if the request is expected to be JSON.
    # Note: If request is JSON, we'll check the data dict.
    data = request.get_json(silent=True) or request.form.to_dict()
    if data.get("hp_field"):  # Hidden honeypot field
        log_security_event("HONEYPOT_TRIGGERED", "Bot detected via hidden field")
        return jsonify({"ok": False, "error": "security_check_failed"}), 403

    token = str(data.get("token", "")).strip().upper()

    # 2. Regex pre-validation (reduce overhead)
    if not re.match(r"^[A-Z0-9-]{4,32}$", token):
        log_security_event("INVALID_TOKEN_FORMAT", f"Attempted token: {token}")
        return jsonify({"ok": False, "error": "Invalid token format"}), 400

    if token_valid(token):
        consume_token(token)          # mark as used — single-use enforcement
        session["authenticated"] = True
        
        # 3. Session Binding (Anti-Hijacking)
        session["fingerprint"] = get_session_fingerprint()
        
        expiry = ACCESS_TOKENS[token]
        log_security_event("TOKEN_VALIDATED", f"Token: {token}")
        return jsonify({
            "ok": True,
            "lifetime": expiry is None,
            "expires": expiry.strftime("%Y-%m-%d") if expiry else None
        })
    
    if token in USED_TOKENS:
        log_security_event("USED_TOKEN_ATTEMPT", f"Token: {token}")
        return jsonify({"ok": False, "error": "Token already used"}), 401
        
    log_security_event("FAILED_TOKEN_ATTEMPT", f"Token: {token}")
    return jsonify({"ok": False, "error": "Invalid or expired token"}), 401


def detect_image_mode(img_bytes):
    """Analyse pixel stats to pick the right enhancement preset."""
    try:
        img = Image.open(BytesIO(img_bytes)).convert("RGB").resize((80, 80))
        # Get pixels efficiently without triggering deprecation warnings
        pixels = list(img.getdata())
        r = sum(p[0] for p in pixels) / len(pixels)
        g = sum(p[1] for p in pixels) / len(pixels)
        b = sum(p[2] for p in pixels) / len(pixels)
        brightness = (r + g + b) / (3 * 255)
        warmth = r / (b + 1e-6)   # red-to-blue ratio; high = warm/yellow cast
        if brightness < 0.38:
            return "dark"
        if warmth > 1.28:
            return "warm"
        return "normal"
    except Exception:
        return "normal"


def process_single_image(input_image_bytes, enhance_mode="auto"):
    """Remove background via remove.bg API and enhance via Cloudinary."""

    # Step 1: Background removal via remove.bg API
    try:
        logger.info("DEBUG: Removing background via remove.bg API...")
        response = requests.post(
            "https://api.remove.bg/v1.0/removebg",
            files={"image_file": ("image.png", input_image_bytes, "image/png")},
            data={"size": "auto"},
            headers={"X-Api-Key": REMOVE_BG_API_KEY},
            timeout=60,
        )
        if response.status_code == 200:
            bg_removed_content = response.content
            logger.info("DEBUG: Background removed successfully via remove.bg")
        elif response.status_code == 402:
            raise ValueError("quota_exceeded:remove_bg:402")
        elif response.status_code == 400:
            raise ValueError("bg_removal_failed:bad_request:400")
        elif response.status_code == 403:
            raise ValueError("bg_removal_failed:invalid_api_key:403")
        else:
            raise ValueError(f"bg_removal_failed:api_error:{response.status_code}")
    except ValueError:
        raise
    except Exception as e:
        logger.error(f"ERROR: remove.bg failed: {e}")
        raise ValueError("bg_removal_failed:network_error:0")

    # Auto-detect image condition if mode not forced by user
    detected_mode = enhance_mode if enhance_mode in ENHANCE_PRESETS else detect_image_mode(input_image_bytes)
    print(f"DEBUG: enhance_mode={enhance_mode}, detected_mode={detected_mode}")

    # Step 2: Photo Enhancement via Cloudinary
    try:
        print(f"DEBUG: Uploading to Cloudinary — preset: {detected_mode}")
        upload_result = cloudinary.uploader.upload(
            bg_removed_content,
            quality="auto:best",
            transformation=ENHANCE_PRESETS[detected_mode]
        )
        enhanced_url = upload_result.get("secure_url")
        if enhanced_url:
            print(f"DEBUG: Enhanced image URL: {enhanced_url}")
            enhanced_response = requests.get(enhanced_url)
            if enhanced_response.ok:
                final_content = enhanced_response.content
            else:
                print(f"WARNING: Failed to download enhanced image: {enhanced_response.status_code}")
                final_content = bg_removed_content
        else:
            print("WARNING: Cloudinary did not return a secure_url")
            final_content = bg_removed_content
    except Exception as e:
        print(f"ERROR: Cloudinary enhancement failed: {e}")
        final_content = bg_removed_content

    img = Image.open(BytesIO(final_content))

    # Keep transparency intact — convert to RGBA so alpha channel is preserved
    if img.mode != "RGBA":
        img = img.convert("RGBA")

    return img, detected_mode


@app.route("/process", methods=["POST"])
@limiter.limit("5 per minute")
def process():
    if not session.get("authenticated"):
        return jsonify({"error": "unauthorized"}), 401
    
    # Session Binding Check
    if session.get("fingerprint") != get_session_fingerprint():
        log_security_event("SESSION_FINGERPRINT_MISMATCH", "Likely session hijacking attempt")
        session.clear()
        return jsonify({"error": "session_expired"}), 401

    print("==== /process endpoint hit ====")

    # Layout settings
    passport_width = int(request.form.get("width", 390))
    passport_height = int(request.form.get("height", 480))
    border = int(request.form.get("border", 2))
    spacing = int(request.form.get("spacing", 10))
    margin_x = 10
    margin_y = 10
    horizontal_gap = 10
    a4_w, a4_h = 2480, 3508

    # Collect images and their copy counts
    images_data = []

    i = 0
    while f"image_{i}" in request.files:
        file = request.files[f"image_{i}"]
        copies = int(request.form.get(f"copies_{i}", 6))
        images_data.append((file.read(), copies))
        i += 1

    # Fallback to single image mode
    if not images_data and "image" in request.files:
        file = request.files["image"]
        copies = int(request.form.get("copies", 6))
        images_data.append((file.read(), copies))

    if not images_data:
        return "No image uploaded", 400

    enhance_mode = request.form.get("enhance_mode", "auto")
    logger.info(f"DEBUG: Processing {len(images_data)} image(s) | enhance_mode={enhance_mode}")
    start_time = time.time()

    # Process all images in parallel
    passport_images = []
    detected_modes = []

    def process_wrapper(img_data_item):
        img_bytes, copies = img_data_item
        img, det_mode = process_single_image(img_bytes, enhance_mode)
        return img, copies, det_mode

    try:
        with ThreadPoolExecutor(max_workers=min(len(images_data), 10)) as executor:
            results = list(executor.map(process_wrapper, images_data))

        for img, copies, det_mode in results:
            detected_modes.append(det_mode)
            img = img.resize((passport_width, passport_height), Image.LANCZOS)
            img = ImageOps.expand(img, border=border, fill=(0, 0, 0, 255))
            passport_images.append((img, copies))

    except Exception as e:
        err_str = str(e)
        if "410" in err_str or "face" in err_str.lower():
            return {"error": "face_detection_failed"}, 410
        elif "429" in err_str or "quota" in err_str.lower() or "402" in err_str:
            return {"error": "quota_exceeded"}, 429
        else:
            print(f"ERROR during parallel processing: {err_str}")
            return {"error": err_str}, 500

    print(f"DEBUG: Total processing time: {time.time() - start_time:.2f}s")

    paste_w = passport_width + 2 * border
    paste_h = passport_height + 2 * border

    # Build all pages
    pages = []
    current_page = Image.new("RGB", (a4_w, a4_h), "white")
    x, y = margin_x, margin_y

    def new_page():
        nonlocal current_page, x, y
        pages.append(current_page)
        current_page = Image.new("RGB", (a4_w, a4_h), "white")
        x, y = margin_x, margin_y

    for passport_img, copies in passport_images:
        for _ in range(copies):
            if x + paste_w > a4_w - margin_x:
                x = margin_x
                y += paste_h + spacing

            if y + paste_h > a4_h - margin_y:
                new_page()

            # Use alpha channel as mask so transparent areas show white A4 background
            mask = passport_img.split()[-1] if passport_img.mode == "RGBA" else None
            current_page.paste(passport_img, (x, y), mask=mask)
            print(f"DEBUG: Placed at x={x}, y={y}")
            x += paste_w + horizontal_gap

    pages.append(current_page)
    print(f"DEBUG: Total pages = {len(pages)}")

    # Export multi-page PDF
    output = BytesIO()
    if len(pages) == 1:
        pages[0].save(output, format="PDF", dpi=(300, 300))
    else:
        pages[0].save(
            output,
            format="PDF",
            dpi=(300, 300),
            save_all=True,
            append_images=pages[1:],
        )
    output.seek(0)
    print("DEBUG: Returning PDF to client")

    resp = send_file(
        output,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="passport-sheet.pdf",
    )
    resp.headers["X-Detected-Mode"] = detected_modes[0] if detected_modes else "normal"
    resp.headers["Access-Control-Expose-Headers"] = "X-Detected-Mode"
    return resp

if __name__ == "__main__":
    # For Windows production, use waitress: pip install waitress
    # run: waitress-serve --port=5000 app:app
    app.run(host="0.0.0.0", port=5000, debug=False)
