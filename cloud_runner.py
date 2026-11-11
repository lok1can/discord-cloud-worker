"""
Bulut (Cloud) 7/24 Discord Çoklu Hesap Aktif Tutucu (Sınırsız & Kesintisiz Mod)
- İçinde hiçbir hesap bilgisi veya token barındırmaz (Şifreli GitHub Secrets kasasından okur).
- 90 saniye soket zaman aşımı (Discord 41.25s Heartbeat ile %100 uyumlu - 1-2 saat sonra düşmez!).
- WebSocket PING (0x9) -> PONG (0xA) otomatik yanıtlayıcı ve soket temizleyici.
- Süre biterken kendi kendini otomatik yeniden başlatan (Self-Chaining) sonsuz döngü.
"""
import os, sys, json, time, uuid, random, hashlib, struct, socket, ssl, base64, threading, urllib.request

def load_accounts_from_vault():
    v_data = os.environ.get("VAULT_DATA", "").strip()
    v_key = os.environ.get("VAULT_KEY", "").strip()
    if not v_data or not v_key:
        return []
    try:
        enc = base64.b64decode(v_data)
        key = base64.b64decode(v_key)
        dec = bytes(enc[i] ^ key[i % len(key)] for i in range(len(enc)))
        return json.loads(dec.decode("utf-8"))
    except Exception as e:
        print("Vault decode error:", e, flush=True)
        return []

ACCOUNTS = load_accounts_from_vault()
START_DELAY = 0

PLATFORMS = {
    "ios": {
        "os": "iOS",
        "browser": "Discord iOS",
        "device": "iPhone16,2",
        "ua": "Discord-iOS/254.0 (iPhone16,2; iOS 17.6.1; Scale/3.00)",
        "version": "254.0",
        "os_version": "17.6.1",
        "build_number": 66094
    },
    "android": {
        "os": "Android",
        "browser": "Discord Android",
        "device": "SM-S928B",
        "ua": "Discord-Android/254012;RNA",
        "version": "254.12 - Stable",
        "os_version": "14",
        "build_number": 254012
    },
    "console": {
        "os": "Linux",
        "browser": "Discord Embedded",
        "device": "PlayStation 5",
        "ua": "Mozilla/5.0 (PlayStation; PlayStation 5/6.00)",
        "version": "1.0",
        "os_version": "6.00",
        "build_number": 298412
    },
    "web": {
        "os": "Windows",
        "browser": "Chrome",
        "device": "",
        "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "version": "128.0.0.0",
        "os_version": "10",
        "build_number": 328451
    }
}

class MinimalWS:
    def __init__(self, host="gateway.discord.gg", path="/?v=10&encoding=json", ua="Discord-iOS/254.0"):
        self.host = host
        self.path = path
        self.ua = ua
        self.sock = None
        self.connected = False
        self.lock = threading.Lock()

    def connect(self):
        raw = socket.create_connection((self.host, 443), timeout=30)
        try:
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except Exception:
            pass
        ctx = ssl.create_default_context()
        try:
            ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        key = base64.b64encode(os.urandom(16)).decode("utf-8")
        hs = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Accept-Language: tr-TR,tr;q=0.9\r\n"
            f"Accept-Encoding: gzip, deflate, br\r\n"
            f"Cache-Control: no-cache\r\n"
            f"Pragma: no-cache\r\n"
            f"User-Agent: {self.ua}\r\n\r\n"
        )
        self.sock.sendall(hs.encode("utf-8"))
        resp = b""
        while b"\r\n\r\n" not in resp:
            ch = self.sock.recv(1024)
            if not ch:
                raise ConnectionError("Handshake failed")
            resp += ch
        # KRİTİK DÜZELTME: Discord Heartbeat süresi 41.25 saniye olduğu için
        # okuma zaman aşımını 95 saniye yapıyoruz (25 saniyede bir kopma hatasını %100 çözer!)
        self.sock.settimeout(95.0)
        self.connected = True

    def send_frame(self, opcode, payload_bytes):
        with self.lock:
            if not self.connected or not self.sock:
                return
            header = bytearray([0x80 | (opcode & 0x0F)])
            l = len(payload_bytes)
            if l < 126:
                header.append(0x80 | l)
            elif l < 65536:
                header.append(0x80 | 126)
                header.extend(struct.pack("!H", l))
            else:
                header.append(0x80 | 127)
                header.extend(struct.pack("!Q", l))
            mask = os.urandom(4)
            header.extend(mask)
            masked = bytearray(payload_bytes[i] ^ mask[i % 4] for i in range(l))
            self.sock.sendall(header + masked)

    def send_json(self, data):
        self.send_frame(0x1, json.dumps(data).encode("utf-8"))

    def recv_json(self):
        b2 = self._recv(2)
        if not b2:
            return None
        op = b2[0] & 0x0F
        masked = (b2[1] & 0x80) != 0
        l = b2[1] & 0x7F
        if l == 126:
            ext = self._recv(2)
            if not ext:
                return None
            l = struct.unpack("!H", ext)[0]
        elif l == 127:
            ext = self._recv(8)
            if not ext:
                return None
            l = struct.unpack("!Q", ext)[0]
        mask = self._recv(4) if masked else None
        p = self._recv(l)
        if p is None:
            return None
        if masked and mask:
            p = bytes(p[i] ^ mask[i % 4] for i in range(l))
        if op == 0x8:  # Close frame
            self.connected = False
            return None
        if op == 0x9:  # WebSocket PING -> PONG ile hemen cevapla (kopmayı önler!)
            try:
                self.send_frame(0xA, p)
            except Exception:
                pass
            return {}
        if op == 0x1:
            return json.loads(p.decode("utf-8", errors="ignore"))
        return {}

    def _recv(self, n):
        buf = b""
        while len(buf) < n:
            try:
                ch = self.sock.recv(n - len(buf))
                if not ch:
                    return None
                buf += ch
            except Exception:
                return None
        return buf

    def close(self):
        self.connected = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

def make_deterministic_uuid(token_str, salt):
    h = hashlib.sha256((token_str + salt).encode("utf-8")).hexdigest()
    return str(uuid.UUID(h[:32]))

def keep_account_online(acc, idx):
    token = acc.get("token", "").strip()
    plat = PLATFORMS.get(acc.get("platform", "ios"), PLATFORMS["ios"])
    status = acc.get("status", "online")
    voice_id = acc.get("voice_channel_id", "").strip()
    guild_id = acc.get("guild_id", "").strip()

    vendor_uuid = make_deterministic_uuid(token, "vendor_ios_v1")
    launch_uuid = make_deterministic_uuid(token, str(int(time.time() // 86400)))

    session_id = None
    last_seq = None
    resume_host = "gateway.discord.gg"

    while True:
        ws = None
        try:
            ws = MinimalWS(host=resume_host, ua=plat["ua"])
            ws.connect()
            hello = ws.recv_json()
            if not hello or hello.get("op") != 10:
                raise ConnectionError("No HELLO")
            hb = hello["d"]["heartbeat_interval"] / 1000.0

            time.sleep(random.uniform(0.4, 0.7))

            if session_id and last_seq is not None:
                print(f"[Hesap #{idx+1}] Mevcut oturum RESUME ediliyor...", flush=True)
                ws.send_json({
                    "op": 6,
                    "d": {
                        "token": token,
                        "session_id": session_id,
                        "seq": last_seq
                    }
                })
            else:
                ws.send_json({
                    "op": 2,
                    "d": {
                        "token": token,
                        "capabilities": 16381,
                        "properties": {
                            "os": plat["os"],
                            "browser": plat["browser"],
                            "device": plat["device"],
                            "system_locale": "tr-TR",
                            "client_version": plat["version"],
                            "release_channel": "stable",
                            "device_vendor_id": vendor_uuid,
                            "browser_user_agent": plat["ua"],
                            "browser_version": plat["version"],
                            "os_version": plat["os_version"],
                            "client_build_number": plat["build_number"],
                            "client_event_source": None,
                            "launch_signature": launch_uuid
                        },
                        "presence": {
                            "status": status,
                            "since": 0,
                            "activities": [],
                            "afk": False
                        },
                        "compress": False
                    }
                })

            last_ack = [time.time()]

            def hb_loop(current_ws):
                while current_ws.connected:
                    time.sleep(hb * random.uniform(0.88, 0.96))
                    if not current_ws.connected:
                        break
                    # Eğer 3 heartbeat boyunca ACK gelmediyse soket donmuştur, yenile
                    if time.time() - last_ack[0] > (hb * 3.2):
                        current_ws.close()
                        break
                    try:
                        current_ws.send_json({"op": 1, "d": last_seq})
                    except Exception:
                        current_ws.close()
                        break
            threading.Thread(target=hb_loop, args=(ws,), daemon=True).start()

            while ws.connected:
                msg = ws.recv_json()
                if msg is None:
                    break
                if msg.get("s") is not None:
                    last_seq = msg["s"]

                op = msg.get("op")
                t = msg.get("t")

                if op == 11:  # Heartbeat ACK
                    last_ack[0] = time.time()
                elif op == 1:  # Discord anlık Heartbeat istediğinde hemen cevap ver
                    ws.send_json({"op": 1, "d": last_seq})
                elif t == "READY":
                    last_ack[0] = time.time()
                    d_data = msg.get("d", {})
                    session_id = d_data.get("session_id")
                    r_url = d_data.get("resume_gateway_url", "")
                    if r_url.startswith("wss://"):
                        resume_host = r_url.replace("wss://", "").strip("/")
                    u = d_data.get("user", {}).get("username", f"Hesap_{idx+1}")
                    print(f"[7/24 KESINTISIZ AKTIF] {u} -> {plat['browser']} ({status})", flush=True)
                    if voice_id:
                        time.sleep(random.uniform(0.7, 1.1))
                        ws.send_json({
                            "op": 4,
                            "d": {
                                "guild_id": guild_id if guild_id else None,
                                "channel_id": voice_id,
                                "self_mute": True,
                                "self_deaf": True,
                                "self_video": False
                            }
                        })
                elif t == "RESUMED":
                    last_ack[0] = time.time()
                    print(f"[Hesap #{idx+1}] Oturum basariyla RESUME edildi (Kesintisiz devam)!", flush=True)
                elif op == 7:  # Reconnect isteği (session korunur)
                    break
                elif op == 9:  # Invalid Session
                    if not msg.get("d"):
                        session_id = None
                        last_seq = None
                        resume_host = "gateway.discord.gg"
                    time.sleep(random.uniform(3.0, 5.0))
                    break
        except Exception as e:
            print(f"[Hesap #{idx+1}] Baglanti yenileniyor: {e}", flush=True)
        finally:
            if ws:
                ws.close()
        time.sleep(random.uniform(3.0, 6.0))

def trigger_next_workflow():
    """
    5.5 saatlik çalışma süresi bitmeden hemen önce bir sonraki 5.5 saatlik bulut görevini
    otomatik olarak tetikler (Sonsuz 7/24 Zincirleme Çalışma).
    """
    gh_token = os.environ.get("GH_DISPATCH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not gh_token or not repo:
        return
    try:
        url = f"https://api.github.com/repos/{repo}/actions/workflows/keepalive.yml/dispatches"
        req = urllib.request.Request(
            url,
            data=json.dumps({"ref": "main"}).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {gh_token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "Discord-KeepAlive-SelfChain"
            },
            method="POST"
        )
        urllib.request.urlopen(req, timeout=15)
        print("[SONSUZ DONGU] Yeni 5.5 saatlik bulut gorevi basariyla tetiklendi!", flush=True)
    except Exception as e:
        print("Self-chain trigger notice:", e, flush=True)

if __name__ == "__main__":
    target_idx = None
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        target_idx = int(sys.argv[1])

    if target_idx is not None and 0 <= target_idx < len(ACCOUNTS):
        print(f"=== IZOLASYON MODU: Hesap #{target_idx+1} Kendi Ozel Sunucusunda (Ayri IP) Baslatildi ===", flush=True)
        threading.Thread(target=keep_account_online, args=(ACCOUNTS[target_idx], target_idx), daemon=True).start()
    else:
        print(f"=== COKLU HESAP KORUMALI MOD BASLATILDI ({len(ACCOUNTS)} Hesap) ===", flush=True)
        for i, a in enumerate(ACCOUNTS):
            if a.get("token"):
                if i > 0:
                    time.sleep(6.0)
                threading.Thread(target=keep_account_online, args=(a, i), daemon=True).start()

    # 5 saat 20 dakika (19200 sn) kesintisiz çalış, sonra bir sonraki vardiyayı otomatik başlat!
    time.sleep(19200)
    if target_idx in (None, 0):
        trigger_next_workflow()
    time.sleep(60)
