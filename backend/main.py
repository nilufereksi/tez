from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
import openai  # lm-studio API bağlantısı için gerekli
import uvicorn
import io
import json
import easyocr
import numpy as np
from PIL import Image
import os
import re
import warnings

# --- AYARLAR ---
warnings.filterwarnings("ignore")
app = FastAPI(title="Siber Güvenlik AI API", version="13.0 - LM STUDIO EDITION")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- LM STUDIO API YAPILANDIRMASI ---
# LM Studio Local Server sekmesindeki URL ve port ile aynı olmalıdır (Genelde 1234)
openai.api_base = "http://localhost:1234/v1" 
openai.api_key = "lm-studio" # Yerel sunucu olduğu için anahtar değeri önemsizdir

print("--- SİSTEM BAŞLATILIYOR (V13.0 - LM STUDIO ENTEGRASYONU) ---")

# 1. OCR (Hızlı Mod)
reader = easyocr.Reader(['en'], gpu=False, verbose=False)

# --- 1. ADIM: PYTHON İLE KESİN TEŞHİS (LEGACY RULES) ---
def detect_vuln_with_legacy_rules(text, filename="uploaded_image.png"):
    text = text.lower()
    filename = filename.lower()
    
    vuln_name = "Potansiyel Güvenlik Uyarısı"
    risk = "Bilinmiyor"
    color = "orange"
    
    # --- ANAHTAR KELİMELER (TAM LİSTE KORUNDU) ---
    idor_keywords = ['basket', '/basket/', 'basketid', 'cart', 'cartid', 'orderid', 'user_id', 'userid', 'account_id', 'member_id', 'admin=true', 'role=admin', 'access denied', 'unauthorized']
    ssrf_keywords = ['169.254.169.254', 'metadata', 'meta-data', 'accesskeyid', 'secretaccesskey', 'security-credentials', 'iam/security-credentials', 'instance-id', 'ssrf', 'server side request forgery']
    logging_keywords = ['wp_debug', 'wp_debug_log', 'wp-config.php', 'define', 'false', 'log_errors = off', 'logging: false', 'no logs found', 'audit log disabled']
    integrity_keywords = ['apache struts', 'struts configuration browser', 'action information', 'debugging_struts', 'deserialization', 'serialize', 'unserialize', 'objectinputstream', 'integrity check failed']
    misconfig_keywords = ['index of', 'parent directory', 'listing directory', 'access-control-allow-origin', 'missing security headers', 'php function', 'php version', 'server name', '403 error', 'forbidden']
    sql_keywords = ['sql syntax', 'mysql_fetch', 'ora-', 'union select', "'1'='1", '1=1', 'sql error', 'warning: mysql', 'vulnerability: sql injection']
    cmd_keywords = ['command injection', 'command execution', 'rce', 'ping ', 'whoami', 'cat /etc/passwd', 'ipconfig', 'system(', 'shell_exec', 'exec(']
    brute_keywords = ['too many failed attempts', 'account has been locked', 'incorrect password', 'login failed', 'brute force', 'kimlik doğrulama başarısız']
    crypto_keywords = ['potential security risk', 'your connection is not private', 'not secure', 'ssl error', 'certificate invalid', 'md5', 'base64', 'plaintext', 'private key']
    design_keywords = ['secutily', 'pastwoad', 'qu onlan', 'email addrest', 'mnal', 'security question', 'mother\'s maiden name', 'quantity: -', 'total: -$']
    outdated_keywords = ['package.json', 'dependencies', 'node_modules', 'vulnerable component', 'outdated version', 'express ^', '.bak', 'backup file']
    xss_keywords = ['alert(', '<script>', 'javascript:', 'onerror=', 'document.cookie', 'stored xss', 'cross-site scripting']
    tool_keywords = ['burp suite', 'owasp zap', 'nmap', 'metasploit', 'wireshark']

    # --- KONTROL MANTIĞI ---
    if "security" in filename and "question" in filename:
        vuln_name = "A04: Insecure Design"; risk = "Yüksek"; color = "orange"
    elif any(x in text for x in idor_keywords):
        vuln_name = "A01: Broken Access Control (IDOR)"; risk = "Kritik"; color = "red"
    elif any(x in text for x in ssrf_keywords):
        vuln_name = "A10: Server-Side Request Forgery (SSRF)"; risk = "Kritik"; color = "red"
    elif any(x in text for x in integrity_keywords):
        vuln_name = "A08: Software and Data Integrity Failures"; risk = "Kritik"; color = "red"
    elif any(x in text for x in logging_keywords):
        vuln_name = "A09: Security Logging Failures"; risk = "Orta"; color = "orange"
    elif any(x in text for x in misconfig_keywords):
        vuln_name = "A05: Security Misconfiguration"; risk = "Orta"; color = "orange"
    elif any(x in text for x in sql_keywords):
        vuln_name = "A03: SQL Injection"; risk = "Kritik"; color = "red"
    elif any(x in text for x in cmd_keywords):
        vuln_name = "A03: Command Injection (RCE)"; risk = "Kritik"; color = "red"
    elif any(x in text for x in crypto_keywords):
        vuln_name = "A02: Cryptographic Failures"; risk = "Yüksek"; color = "red"
    elif any(x in text for x in brute_keywords):
        vuln_name = "A07: Identification and Auth Failures"; risk = "Yüksek"; color = "red"
    elif any(x in text for x in design_keywords):
        vuln_name = "A04: Insecure Design"; risk = "Yüksek"; color = "orange"
    elif any(x in text for x in outdated_keywords):
        vuln_name = "A06: Vulnerable/Outdated Components"; risk = "Yüksek"; color = "orange"
    elif any(x in text for x in xss_keywords):
        vuln_name = "A03: Cross-Site Scripting (XSS)"; risk = "Yüksek"; color = "red"
    elif any(x in text for x in tool_keywords):
        vuln_name = "Güvenlik Aracı Taraması"; risk = "Bilgi"; color = "grey"

    return {"bulgu": vuln_name, "risk": risk, "color": color}


# --- 2. ADIM: JSON TAMİR (TAMAMI KORUNDU) ---
def repair_and_parse(text, forced_data):
    if not text: return None
    text = text.replace("```json", "").replace("```", "").strip()

    cozum_match = re.search(r'"(kb_cozum|solution|fix)":\s*"(.*?)"', text, re.IGNORECASE | re.DOTALL)
    nedir_match = re.search(r'"(kb_nedir|desc|description)":\s*"(.*?)"', text, re.IGNORECASE | re.DOTALL)

    cozum = cozum_match.group(2).replace('"', "'").strip() if cozum_match else "Sistem yöneticisine başvurun ve güvenlik yamalarını uygulayın."
    nedir = nedir_match.group(2).replace('"', "'").strip() if nedir_match else "Sistem üzerinde şüpheli bir güvenlik aktivitesi tespit edildi."

    return {
        "results": [{
            "bulgu": forced_data["bulgu"], 
            "risk": forced_data["risk"],   
            "kb_cozum": cozum,             
            "kb_nedir": nedir,             
            "color": forced_data["color"]  
        }]
    }


# --- 3. ADIM: HİBRİT MOTOR (LM STUDIO API ÇAĞRISI) ---
def get_ai_response_hybrid(user_text):
    # A) Python ile teşhis koy
    detected = detect_vuln_with_legacy_rules(user_text)
    print(f"DEBUG: Python Teşhisi -> {detected['bulgu']}")

    # B) LM Studio üzerindeki Llama-3 modeline istek gönder
    vuln_title = detected["bulgu"]
    
    prompt = f"""
Sen Kıdemli bir Siber Güvenlik Uzmanısın. Görevin: "{vuln_title}" zafiyeti için Türkçe rapor üretmek.
Çıktı Formatı: Sadece JSON.
ÖRNEK:
{{
  "kb_cozum": "Girdi doğrulaması yapılmalı...",
  "kb_nedir": "SQL Enjeksiyonu, saldırganın..."
}}
Zafiyet: {vuln_title}
Log Bağlamı: {user_text[:500]}
"""

    try:
        # LM Studio üzerinden analiz alıyoruz
        response = openai.ChatCompletion.create(
            model="local-model", # LM Studio'da o an yüklü olan modeli kullanır
            messages=[
                {"role": "system", "content": "Sen sadece JSON formatında yanıt veren profesyonel bir siber güvenlik asistanısın."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        
        full_text = response.choices[0].message.content
        print(f" AI Açıklaması (LM Studio): {full_text[:50]}...")

        return repair_and_parse(full_text, forced_data=detected)

    except Exception as e:
        print(f"LM Studio Bağlantı Hatası: {e}")
        return {
            "results": [{
                "bulgu": detected["bulgu"],
                "risk": detected["risk"],
                "kb_cozum": "LM Studio sunucusunun açık olduğundan emin olun.",
                "kb_nedir": "AI modeline ulaşılamadığı için manuel kural sonucu döndürüldü.",
                "color": detected["color"]
            }]
        }

@app.post("/analyze/image")
async def analyze_image(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        image = Image.open(io.BytesIO(contents))
        ocr_result = reader.readtext(np.array(image), detail=0)
        text = " ".join(ocr_result)
        
        if len(text) < 3:
             return {"results": [{"bulgu": "Metin Okunamadı", "risk": "-", "kb_cozum": "-", "kb_nedir": "-", "color": "grey"}]}
        
        return get_ai_response_hybrid(text)

    except Exception as e:
        return {"results": [{"bulgu": "Sunucu Hatası", "risk": "Critical", "kb_cozum": str(e), "kb_nedir": "API Crash", "color": "red"}]}


from fastapi import Request
@app.post("/analyze/json")
async def analyze_json(request: Request):
    try:
        # Gelen ham veriyi oku
        body_bytes = await request.body()
        
        # Byte verisini metne (UTF-8) çevir
        # Eğer dosya olarak geliyorsa içindeki metni ayıklar
        raw_text = body_bytes.decode("utf-8", errors="ignore")
        
        # Temizlik: JSON içindeki gereksiz karakterleri ve tırnakları temizle
        clean_text = raw_text.strip().replace('\\n', ' ').replace('\\"', '"')

        print(f"DEBUG: JSON Verisi Alındı -> {clean_text[:100]}...")

        # Analiz motoruna gönder
        return get_ai_response_hybrid(clean_text)

    except Exception as e:
        print(f"JSON Hatası: {str(e)}")
        return {"results": [{"bulgu": "JSON Analiz Hatası", "risk": "Critical", "kb_nedir": f"Veri okunamadı: {str(e)}", "color": "red"}]}


if __name__ == "__main__":
    # Kodun bulunduğu dosya adının 'main.py' olduğundan emin olun.
    uvicorn.run("main:app", host="127.0.0.1", port=5001)
