
import json
import re
import shutil
import tempfile
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests
import tkinter as tk
from tkinter import ttk, messagebox

try:
    from PIL import Image, ImageTk
except ImportError:
    Image = ImageTk = None

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:
    sync_playwright = None
    PlaywrightTimeoutError = Exception


APP = "FrameGuard"
VERSION = "7.3"
OUT = Path("FrameGuard_Reports")
OUT.mkdir(exist_ok=True)
TIMEOUT = 20
UA = f"FrameGuard/{VERSION} (authorized clickjacking assessment)"


def normalize_url(value):
    value = value.strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    return value


def origin(url):
    p = urlparse(url)
    if not p.scheme or not p.hostname:
        return ""
    port = p.port
    if (p.scheme == "https" and port in (None, 443)) or (p.scheme == "http" and port in (None, 80)):
        return f"{p.scheme.lower()}://{p.hostname.lower()}"
    return f"{p.scheme.lower()}://{p.hostname.lower()}:{port}"


def header_value(headers, name):
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def parse_frame_ancestors(csp):
    m = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp or "", re.I)
    return m.group(1).strip() if m else ""


class FrameGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("FrameGuard — Clickjacking Assessment")
        self.root.geometry("1180x780")
        self.root.minsize(1000, 700)

        self.bg = "#0b1020"
        self.panel = "#121a2d"
        self.panel2 = "#17223a"
        self.text = "#e8eefc"
        self.muted = "#9aa8c7"
        self.accent = "#62d8ff"

        self.root.configure(bg=self.bg)
        self.temp_dirs = []
        self.last_analysis = None

        self._style()
        self._ui()

    def _style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure("TFrame", background=self.bg)
        s.configure("Panel.TFrame", background=self.panel)
        s.configure("TLabel", background=self.bg, foreground=self.text, font=("Segoe UI", 10))
        s.configure("Title.TLabel", background=self.bg, foreground=self.text, font=("Segoe UI Semibold", 22))
        s.configure("Muted.TLabel", background=self.bg, foreground=self.muted, font=("Segoe UI", 9))
        s.configure("TButton", font=("Segoe UI Semibold", 10), padding=(12, 8))
        s.configure("Accent.TButton", foreground="#06111c", background=self.accent)
        s.map("Accent.TButton", background=[("active", "#8be4ff")])
        s.configure("Treeview", background=self.panel, fieldbackground=self.panel, foreground=self.text, rowheight=29)
        s.configure("Treeview.Heading", background=self.panel2, foreground=self.text)

    def _ui(self):
        top = ttk.Frame(self.root)
        top.pack(fill="x", padx=22, pady=(18, 8))
        ttk.Label(top, text="FRAMEGUARD", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text="  Clickjacking / Framing Verification", style="Muted.TLabel").pack(side="left", pady=(8, 0))

        inp = ttk.Frame(self.root)
        inp.pack(fill="x", padx=22, pady=8)
        ttk.Label(inp, text="Target URL").pack(anchor="w")
        row = ttk.Frame(inp)
        row.pack(fill="x", pady=(5, 0))
        self.url_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.url_var, font=("Segoe UI", 11)).pack(side="left", fill="x", expand=True, ipady=6)
        ttk.Button(row, text="Analyze", style="Accent.TButton", command=self.analyze).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Browser Test", command=self.browser_test).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Preview PoC", command=self.preview_poc).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="SAMEORIGIN Verification", command=self.sameorigin_verify).pack(side="left", padx=(8, 0))
        ttk.Button(row, text="Visual Test Matrix", style="Accent.TButton", command=self.visual_matrix).pack(side="left", padx=(8, 0))

        self.status = tk.StringVar(value="Ready — enter an authorized target.")
        ttk.Label(self.root, textvariable=self.status, style="Muted.TLabel").pack(fill="x", padx=22, pady=(0, 8))

        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True, padx=22, pady=(0, 18))

        left = ttk.Frame(body, style="Panel.TFrame")
        left.pack(side="left", fill="both", expand=True, padx=(0, 8))
        right = ttk.Frame(body, style="Panel.TFrame")
        right.pack(side="left", fill="both", expand=True, padx=(8, 0))

        ttk.Label(left, text="Framing Policy", background=self.panel, foreground=self.text,
                  font=("Segoe UI Semibold", 12)).pack(anchor="w", padx=14, pady=(12, 5))
        self.tree = ttk.Treeview(left, columns=("item", "value"), show="headings", height=11)
        self.tree.heading("item", text="Check")
        self.tree.heading("value", text="Result")
        self.tree.column("item", width=200)
        self.tree.column("value", width=420)
        self.tree.pack(fill="both", expand=True, padx=12, pady=8)

        ttk.Label(right, text="Assessment Log", background=self.panel, foreground=self.text,
                  font=("Segoe UI Semibold", 12)).pack(anchor="w", padx=14, pady=(12, 5))
        self.log = tk.Text(right, bg=self.panel2, fg=self.text, insertbackground=self.text,
                           relief="flat", wrap="word", font=("Consolas", 9))
        self.log.pack(fill="both", expand=True, padx=12, pady=8)

        foot = ttk.Frame(self.root)
        foot.pack(fill="x", padx=22, pady=(0, 12))
        ttk.Label(foot, text=f"FrameGuard v{VERSION} • Non-destructive framing verification", style="Muted.TLabel").pack(side="left")
        ttk.Button(foot, text="Clear", command=self.clear).pack(side="right")

    def log_line(self, msg):
        self.log.insert("end", f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
        self.log.see("end")

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.log.delete("1.0", "end")
        self.last_analysis = None
        self.status.set("Ready — enter an authorized target.")

    def target(self):
        u = normalize_url(self.url_var.get())
        if not u:
            messagebox.showwarning(APP, "Enter a target URL.")
            return None
        p = urlparse(u)
        if p.scheme not in ("http", "https") or not p.hostname:
            messagebox.showerror(APP, "Only valid HTTP/HTTPS URLs are supported.")
            return None
        return u

    def analyze(self):
        url = self.target()
        if not url:
            return
        self.status.set("Analyzing framing controls…")
        try:
            r = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent": UA})
            xfo = header_value(r.headers, "X-Frame-Options")
            csp = header_value(r.headers, "Content-Security-Policy")
            fa = parse_frame_ancestors(csp)
            self.last_analysis = {
                "input_url": url,
                "final_url": r.url,
                "status": r.status_code,
                "x_frame_options": xfo,
                "content_security_policy": csp,
                "frame_ancestors": fa,
                "origin": origin(r.url),
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "headers": dict(r.headers),
            }
            self.tree.delete(*self.tree.get_children())
            for a, b in [
                ("HTTP status", str(r.status_code)),
                ("Final URL", r.url),
                ("Origin", origin(r.url)),
                ("X-Frame-Options", xfo or "NOT PRESENT"),
                ("CSP", csp or "NOT PRESENT"),
                ("frame-ancestors", fa or "NOT FOUND"),
            ]:
                self.tree.insert("", "end", values=(a, b))
            self.log_line(f"Final URL: {r.url}")
            self.log_line(f"X-Frame-Options: {xfo or 'NOT PRESENT'}")
            self.log_line(f"frame-ancestors: {fa or 'NOT FOUND'}")
            self.status.set("Analysis complete.")
        except Exception as e:
            self.status.set("Analysis failed.")
            self.log_line(f"ERROR: {e}")
            messagebox.showerror(APP, str(e))

    def _make_poc(self, url):
        temp = Path(tempfile.mkdtemp(prefix="frameguard_"))
        html = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>FrameGuard PoC Preview</title>
<style>
html,body{{margin:0;width:100%;height:100%;background:#10182a;color:#e8eefc;font:14px Segoe UI}}
.bar{{padding:12px 16px;background:#17223a;box-sizing:border-box}}
iframe{{display:block;width:100%;height:calc(100vh - 48px);border:0;background:#fff}}
</style></head>
<body>
<div class="bar">FrameGuard controlled clickjacking preview — {url}</div>
<iframe id="target-frame" src="{url}" title="Controlled framing preview"></iframe>
</body></html>"""
        path = temp / "poc.html"
        path.write_text(html, encoding="utf-8")
        return temp, path

    def _probe_frame(self, url, screenshot=True):
        """
        Returns actual browser observations.
        Crucially, 'iframe element exists' is NOT considered successful framing.
        """
        result = {
            "target": url,
            "frame_url": "",
            "frame_present": False,
            "frame_attached": False,
            "frame_body_text": "",
            "frame_title": "",
            "target_response_status": None,
            "target_response_headers": {},
            "console_errors": [],
            "rendered": False,
            "screenshot": None,
            "error": "",
        }

        temp, poc = self._make_poc(url)
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1280, "height": 760})

                def on_response(resp):
                    if resp.url.rstrip("/") == url.rstrip("/"):
                        result["target_response_status"] = resp.status
                        result["target_response_headers"] = dict(resp.headers)

                def on_console(msg):
                    txt = msg.text or ""
                    if "frame" in txt.lower() or "display" in txt.lower() or "refused" in txt.lower() or "x-frame" in txt.lower():
                        result["console_errors"].append(txt)

                page.on("response", on_response)
                page.on("console", on_console)

                page.goto(poc.as_uri(), wait_until="domcontentloaded", timeout=TIMEOUT * 1000)
                page.wait_for_timeout(3000)

                iframe = page.locator("#target-frame")
                result["frame_present"] = iframe.count() == 1

                target_frame = None
                for fr in page.frames:
                    if fr != page.main_frame and fr.url:
                        # Prefer the frame whose URL matches the requested target.
                        if fr.url.rstrip("/") == url.rstrip("/") or urlparse(fr.url).hostname == urlparse(url).hostname:
                            target_frame = fr
                            break

                if target_frame:
                    result["frame_attached"] = True
                    result["frame_url"] = target_frame.url
                    try:
                        result["frame_title"] = target_frame.title()
                    except Exception:
                        pass
                    try:
                        txt = target_frame.locator("body").inner_text(timeout=2500)
                        result["frame_body_text"] = (txt or "").strip()[:2000]
                    except Exception:
                        result["frame_body_text"] = ""

                # A real content signal is required. This avoids the old false-positive
                # where every iframe was reported as "rendered".
                body_signal = len(result["frame_body_text"].strip()) >= 8
                title_signal = bool(result["frame_title"].strip())
                status_signal = result["target_response_status"] in range(200, 400)
                console_block = any(
                    "refused to display" in x.lower() or
                    "x-frame-options" in x.lower() or
                    "frame-ancestors" in x.lower()
                    for x in result["console_errors"]
                )

                result["rendered"] = bool(
                    result["frame_attached"] and
                    status_signal and
                    (body_signal or title_signal) and
                    not console_block
                )

                if screenshot:
                    result["screenshot"] = page.screenshot(full_page=True)

                browser.close()
        except Exception as e:
            result["error"] = str(e)
        finally:
            shutil.rmtree(temp, ignore_errors=True)

        return result

    def preview_poc(self):
        url = self.target()
        if not url:
            return
        if sync_playwright is None:
            messagebox.showerror(APP, "Playwright is not installed. Run the installation command from README.")
            return
        self.status.set("Testing the actual framed document…")
        self.log_line("PoC preview: checking actual target rendering, not just iframe presence.")
        threading.Thread(target=self._preview_worker, args=(url,), daemon=True).start()

    def _preview_worker(self, url):
        result = self._probe_frame(url, screenshot=True)
        self.root.after(0, lambda: self._show_preview(url, result))

    def _show_preview(self, url, result):
        win = tk.Toplevel(self.root)
        win.title("FrameGuard — PoC Preview")
        win.geometry("1100x800")
        win.configure(bg=self.bg)
        win.transient(self.root)
        win.grab_set()

        ttk.Label(win, text="PoC PREVIEW", style="Title.TLabel").pack(anchor="w", padx=18, pady=(15, 2))
        ttk.Label(win, text=url, style="Muted.TLabel").pack(anchor="w", padx=18)

        if result["error"]:
            state = "PREVIEW ERROR"
        elif result["rendered"]:
            state = "TARGET CONTENT RENDERED INSIDE FRAME"
        else:
            state = "TARGET CONTENT NOT CONFIRMED INSIDE FRAME"

        state_frame = ttk.Frame(win, style="Panel.TFrame")
        state_frame.pack(fill="x", padx=18, pady=10)
        ttk.Label(
            state_frame,
            text=f"  {state}  ",
            foreground=("#63e6be" if result["rendered"] else "#ffd166"),
            background=self.panel,
            font=("Segoe UI Semibold", 12),
        ).pack(side="left", padx=10, pady=9)
        ttk.Label(
            state_frame,
            text=f"iframe element: {'present' if result['frame_present'] else 'missing'}  •  "
                 f"target response: {result['target_response_status'] or 'unknown'}",
            style="Muted.TLabel",
        ).pack(side="left", padx=10)

        holder = ttk.Frame(win, style="Panel.TFrame")
        holder.pack(fill="both", expand=True, padx=18, pady=6)
        image_label = ttk.Label(holder, background=self.panel)
        image_label.pack(expand=True, padx=8, pady=8)

        photo_ref = {"photo": None}
        shot = result.get("screenshot")
        if shot and Image and ImageTk:
            try:
                from io import BytesIO
                img = Image.open(BytesIO(shot)).convert("RGB")
                max_w, max_h = 1020, 575
                ratio = min(max_w / img.width, max_h / img.height, 1)
                img = img.resize((max(1, int(img.width * ratio)), max(1, int(img.height * ratio))))
                photo_ref["photo"] = ImageTk.PhotoImage(img)
                image_label.configure(image=photo_ref["photo"])
            except Exception as e:
                image_label.configure(text=f"Screenshot preview unavailable: {e}")
        else:
            image_label.configure(text="Install Pillow to display the browser screenshot.")

        details = ttk.Frame(win)
        details.pack(fill="x", padx=18, pady=(4, 8))
        msg = (
            "Verified render signal detected: target frame contains browser-accessible document content."
            if result["rendered"]
            else
            "No verified render signal. A visible iframe box alone is NOT treated as a clickjacking finding."
        )
        ttk.Label(details, text=msg, style="Muted.TLabel").pack(anchor="w")

        if result["console_errors"]:
            ttk.Label(details, text="Browser messages:", style="Muted.TLabel").pack(anchor="w", pady=(5, 0))
            ttk.Label(details, text=" • ".join(result["console_errors"][:2]), style="Muted.TLabel").pack(anchor="w")

        buttons = ttk.Frame(win)
        buttons.pack(fill="x", padx=18, pady=12)

        temp, poc = self._make_poc(url)

        def open_browser():
            webbrowser.open(poc.as_uri())

        def discard():
            shutil.rmtree(temp, ignore_errors=True)
            win.grab_release()
            win.destroy()
            self.status.set("PoC preview discarded; no evidence saved.")

        def save():
            out = OUT / f"FrameGuard_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            out.mkdir(parents=True, exist_ok=True)
            shutil.copy2(poc, out / "poc.html")
            if shot:
                (out / "preview.png").write_bytes(shot)

            meta = {
                "tool": APP,
                "version": VERSION,
                "target": url,
                "saved_at": datetime.now().isoformat(timespec="seconds"),
                "browser_observation": {
                    "rendered": result["rendered"],
                    "iframe_element_present": result["frame_present"],
                    "frame_attached": result["frame_attached"],
                    "frame_url": result["frame_url"],
                    "target_response_status": result["target_response_status"],
                    "frame_title": result["frame_title"],
                    "body_text_signal": bool(result["frame_body_text"]),
                    "console_messages": result["console_errors"],
                },
                "interpretation": (
                    "Target content rendering was confirmed by multiple browser signals."
                    if result["rendered"]
                    else
                    "Target content rendering was not confirmed. Do not treat iframe presence alone as proof."
                ),
                "assessment_note": "Sensitive-action impact is not demonstrated by this tool.",
            }
            (out / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
            shutil.rmtree(temp, ignore_errors=True)
            win.grab_release()
            win.destroy()
            self.status.set(f"Evidence saved: {out}")
            self.log_line(f"PoC evidence saved: {out}")

        ttk.Button(buttons, text="Open Interactive Browser", command=open_browser).pack(side="left")
        ttk.Button(buttons, text="Discard", command=discard).pack(side="right", padx=(8, 0))
        ttk.Button(buttons, text="Save Evidence", style="Accent.TButton", command=save).pack(side="right")

        win.protocol("WM_DELETE_WINDOW", discard)

    def browser_test(self):
        url = self.target()
        if not url:
            return
        if sync_playwright is None:
            messagebox.showerror(APP, "Playwright is not installed.")
            return
        self.status.set("Running browser framing test…")
        threading.Thread(target=self._browser_worker, args=(url,), daemon=True).start()

    def _browser_worker(self, url):
        result = self._probe_frame(url, screenshot=True)
        self.root.after(0, lambda: self._browser_done(url, result))

    def _browser_done(self, url, result):
        if result["error"]:
            self.status.set("Browser test failed.")
            self.log_line(f"Browser error: {result['error']}")
            messagebox.showerror(APP, result["error"])
            return
        state = "RENDERED" if result["rendered"] else "NOT CONFIRMED / BLOCKED"
        self.status.set(f"Browser test: {state}")
        self.log_line(f"Actual framed-content result: {state}")
        self.log_line(f"iframe element present: {result['frame_present']}")
        self.log_line(f"target response status: {result['target_response_status']}")
        if result["console_errors"]:
            self.log_line("Browser message: " + result["console_errors"][0])


    def visual_matrix(self):
        """Run a focused clickjacking/framing test matrix and show per-test evidence."""
        url = self.target()
        if not url:
            return
        if sync_playwright is None:
            messagebox.showerror(APP, "Playwright is not installed.")
            return

        self.status.set("Running visual framing test matrix…")
        self.log_line("Visual Test Matrix started.")
        threading.Thread(target=self._matrix_worker, args=(url,), daemon=True).start()

    def _matrix_worker(self, url):
        results = []
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(viewport={"width": 1280, "height": 760})

                # Helper: run a single controlled framing page and collect screenshot +
                # actual child-frame/content signals. The iframe element alone is never
                # considered a successful render.
                def run_case(name, target_url, page_html, viewport=(1280, 760)):
                    page = browser.new_page(viewport={"width": viewport[0], "height": viewport[1]})
                    console = []
                    responses = []

                    page.on("console", lambda msg: console.append(msg.text or ""))
                    page.on("response", lambda resp: responses.append((resp.url, resp.status, dict(resp.headers))))

                    tmp = Path(tempfile.mkdtemp(prefix="frameguard_matrix_"))
                    f = tmp / "matrix.html"
                    f.write_text(page_html, encoding="utf-8")

                    item = {
                        "name": name,
                        "target": target_url,
                        "status": "NOT CONFIRMED",
                        "target_status": None,
                        "frame_url": "",
                        "frame_title": "",
                        "body_signal": False,
                        "console": [],
                        "screenshot": None,
                        "viewport": {"width": viewport[0], "height": viewport[1]},
                    }

                    try:
                        page.goto(f.as_uri(), wait_until="domcontentloaded", timeout=TIMEOUT * 1000)
                        page.wait_for_timeout(2800)

                        target_response = None
                        target_host = (urlparse(target_url).hostname or "").lower()
                        for u, st, hdrs in responses:
                            if (urlparse(u).hostname or "").lower() == target_host:
                                target_response = (st, hdrs)
                        if target_response:
                            item["target_status"] = target_response[0]

                        child = None
                        for fr in page.frames:
                            if fr != page.main_frame and fr.url:
                                if (urlparse(fr.url).hostname or "").lower() == target_host:
                                    child = fr
                                    break

                        if child:
                            item["frame_url"] = child.url
                            try:
                                item["frame_title"] = child.title()
                            except Exception:
                                pass
                            try:
                                body = child.locator("body").inner_text(timeout=2500).strip()
                                item["body_signal"] = len(body) >= 8
                            except Exception:
                                pass

                        relevant_console = [
                            x for x in console
                            if any(k in x.lower() for k in
                                   ("refused to display", "frame-ancestors", "x-frame-options", "refused"))
                        ]
                        item["console"] = relevant_console[:5]

                        status_ok = item["target_status"] in range(200, 400)
                        content_signal = bool(item["body_signal"] or item["frame_title"].strip())
                        blocked_signal = bool(relevant_console)

                        if child and status_ok and content_signal and not blocked_signal:
                            item["status"] = "RENDERED"
                        elif blocked_signal:
                            item["status"] = "BLOCKED"
                        else:
                            item["status"] = "NOT CONFIRMED"

                        item["screenshot"] = page.screenshot(full_page=True)
                    except Exception as e:
                        item["status"] = "ERROR"
                        item["error"] = str(e)
                    finally:
                        page.close()
                        shutil.rmtree(tmp, ignore_errors=True)

                    return item

                # Case 1: direct external framing from a local file origin.
                direct_html = f"""<!doctype html><html><body>
                <div style="font:14px Segoe UI">FrameGuard — Direct cross-origin framing test</div>
                <iframe src="{url}" style="width:100%;height:650px;border:0"></iframe>
                </body></html>"""
                results.append(run_case("Direct Cross-Origin", url, direct_html))

                # Case 2: same target URL using the same controlled document origin.
                same_html = f"""<!doctype html><html><body>
                <div style="font:14px Segoe UI">FrameGuard — Same-origin comparison</div>
                <iframe src="{url}" style="width:100%;height:650px;border:0"></iframe>
                </body></html>"""
                results.append(run_case("Controlled Framing", url, same_html))

                # Case 3: hostname variant.
                p = urlparse(url)
                host = p.hostname or ""
                variant_host = host[4:] if host.lower().startswith("www.") else "www." + host
                variant = f"{p.scheme}://{variant_host}{p.path or '/'}"
                if p.query:
                    variant += "?" + p.query
                variant_html = f"""<!doctype html><html><body>
                <div style="font:14px Segoe UI">FrameGuard — Hostname variant test</div>
                <iframe src="{variant}" style="width:100%;height:650px;border:0"></iframe>
                </body></html>"""
                results.append(run_case("Hostname Variant", variant, variant_html))

                # Case 4: nested ancestor chain.
                nested_html = f"""<!doctype html><html><body>
                <div style="font:14px Segoe UI">FrameGuard — Nested ancestor test</div>
                <iframe srcdoc="<iframe src='{url}' style='width:100%;height:620px;border:0'></iframe>"
                        style="width:100%;height:650px;border:0"></iframe>
                </body></html>"""
                results.append(run_case("Nested Frame", url, nested_html))

                # Case 5: redirect-aware final URL. Resolve with requests, then frame final target.
                try:
                    rr = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent": UA})
                    final_url = rr.url
                except Exception:
                    final_url = url
                redirect_html = f"""<!doctype html><html><body>
                <div style="font:14px Segoe UI">FrameGuard — Redirect final-target test</div>
                <iframe src="{final_url}" style="width:100%;height:650px;border:0"></iframe>
                </body></html>"""
                results.append(run_case("Redirect Final Target", final_url, redirect_html))

                browser.close()

            self.root.after(0, lambda: self._show_matrix(url, results))
        except Exception as e:
            err = str(e)
            self.root.after(0, lambda err=err: messagebox.showerror(APP, err))

    def _show_matrix(self, url, results):
        win = tk.Toplevel(self.root)
        win.title("FrameGuard — Visual Test Matrix")
        win.geometry("1180x820")
        win.configure(bg=self.bg)
        win.transient(self.root)
        win.grab_set()

        ttk.Label(win, text="VISUAL TEST MATRIX", style="Title.TLabel").pack(anchor="w", padx=18, pady=(15, 2))
        ttk.Label(win, text=url, style="Muted.TLabel").pack(anchor="w", padx=18)

        summary = ttk.Frame(win, style="Panel.TFrame")
        summary.pack(fill="x", padx=18, pady=12)

        rendered = sum(1 for r in results if r["status"] == "RENDERED")
        blocked = sum(1 for r in results if r["status"] == "BLOCKED")
        unknown = sum(1 for r in results if r["status"] not in ("RENDERED", "BLOCKED"))
        ttk.Label(
            summary,
            text=f"  {len(results)} tests   •   {rendered} rendered   •   {blocked} blocked   •   {unknown} not confirmed  ",
            background=self.panel, foreground=self.text,
            font=("Segoe UI Semibold", 11)
        ).pack(anchor="w", padx=10, pady=10)

        table_frame = ttk.Frame(win, style="Panel.TFrame")
        table_frame.pack(fill="both", expand=True, padx=18, pady=(0, 8))

        cols = ("test", "status", "http", "frame", "signal", "evidence")
        tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=10)
        headings = {
            "test": "Test", "status": "Result", "http": "HTTP",
            "frame": "Child Frame", "signal": "Content Signal", "evidence": "Evidence"
        }
        widths = {"test": 190, "status": 150, "http": 80, "frame": 110, "signal": 120, "evidence": 100}
        for c in cols:
            tree.heading(c, text=headings[c])
            tree.column(c, width=widths[c], anchor="center")
        tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=tree.yview)
        scroll.pack(side="right", fill="y", pady=10)
        tree.configure(yscrollcommand=scroll.set)

        for i, r in enumerate(results):
            tree.insert(
                "", "end", iid=str(i),
                values=(
                    r["name"], r["status"],
                    r.get("target_status") or "—",
                    "YES" if r.get("frame_url") else "NO",
                    "YES" if (r.get("body_signal") or r.get("frame_title")) else "NO",
                    "View"
                )
            )

        ttk.Label(
            win,
            text="Click the View cell in any row to open that test's screenshot.",
            style="Muted.TLabel"
        ).pack(anchor="w", padx=18, pady=(0, 4))

        detail = tk.Text(win, height=8, bg=self.panel2, fg=self.text,
                         insertbackground=self.text, relief="flat",
                         wrap="word", font=("Consolas", 9))
        detail.pack(fill="x", padx=18, pady=8)

        def show_selected(event=None):
            sel = tree.selection()
            if not sel:
                return
            r = results[int(sel[0])]
            detail.delete("1.0", "end")
            detail.insert("end", f"TEST: {r['name']}\n")
            detail.insert("end", f"TARGET: {r['target']}\n")
            detail.insert("end", f"RESULT: {r['status']}\n")
            detail.insert("end", f"HTTP: {r.get('target_status') or 'unknown'}\n")
            detail.insert("end", f"FRAME URL: {r.get('frame_url') or 'not observed'}\n")
            detail.insert("end", f"TITLE SIGNAL: {r.get('frame_title') or 'none'}\n")
            detail.insert("end", f"BODY SIGNAL: {'yes' if r.get('body_signal') else 'no'}\n")
            if r.get("console"):
                detail.insert("end", "BROWSER MESSAGES:\n" + "\n".join("  " + x for x in r["console"]) + "\n")
            detail.insert("end", "\nA frame element by itself is not treated as successful rendering.")

        tree.bind("<<TreeviewSelect>>", show_selected)

        def on_matrix_click(event):
            row_id = tree.identify_row(event.y)
            col_id = tree.identify_column(event.x)
            if row_id and col_id == "#6":
                tree.selection_set(row_id)
                tree.focus(row_id)
                view_evidence(int(row_id))

        tree.bind("<Button-1>", on_matrix_click)
        tree.bind("<Double-1>", lambda event: (
            view_evidence(int(tree.identify_row(event.y)))
            if tree.identify_row(event.y) and tree.identify_column(event.x) == "#6"
            else None
        ))
        tree.configure(cursor="hand2")

        image_win = {"win": None, "photo": None}

        def view_evidence(index=None):
            if index is None:
                sel = tree.selection()
                if not sel:
                    messagebox.showinfo(APP, "Select a test first.")
                    return
                index = int(sel[0])
            r = results[index]
            shot = r.get("screenshot")
            if not shot:
                messagebox.showinfo(APP, "No screenshot was captured for this test.")
                return

            if image_win["win"] and image_win["win"].winfo_exists():
                image_win["win"].lift()
                return

            iw = tk.Toplevel(win)
            image_win["win"] = iw
            iw.title(f"Evidence — {r['name']}")
            iw.geometry("1050x720")
            iw.configure(bg=self.bg)

            ttk.Label(iw, text=r["name"], style="Title.TLabel").pack(anchor="w", padx=16, pady=(14, 2))
            ttk.Label(iw, text=f"{r['status']} • {r['target']}", style="Muted.TLabel").pack(anchor="w", padx=16)

            holder = ttk.Frame(iw, style="Panel.TFrame")
            holder.pack(fill="both", expand=True, padx=16, pady=12)
            label = ttk.Label(holder, background=self.panel)
            label.pack(expand=True)

            if Image and ImageTk:
                from io import BytesIO
                img = Image.open(BytesIO(shot)).convert("RGB")
                max_w, max_h = 980, 600
                ratio = min(max_w / img.width, max_h / img.height, 1)
                img = img.resize((max(1, int(img.width * ratio)), max(1, int(img.height * ratio))))
                photo = ImageTk.PhotoImage(img)
                image_win["photo"] = photo
                label.configure(image=photo)
            else:
                label.configure(text="Install Pillow to view screenshots.")

            iw.protocol("WM_DELETE_WINDOW", lambda: (iw.destroy(), image_win.update({"win": None, "photo": None})))

        def save_matrix():
            out = OUT / f"FrameGuard_Matrix_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            out.mkdir(parents=True, exist_ok=True)

            report = {
                "tool": APP,
                "version": VERSION,
                "target": url,
                "created_at": datetime.now().isoformat(timespec="seconds"),
                "tests": []
            }

            for i, r in enumerate(results, start=1):
                entry = {k: v for k, v in r.items() if k != "screenshot"}
                shot = r.get("screenshot")
                if shot:
                    filename = f"{i:02d}_{re.sub(r'[^A-Za-z0-9_-]+', '_', r['name'])}.png"
                    (out / filename).write_bytes(shot)
                    entry["screenshot"] = filename
                report["tests"].append(entry)

            (out / "matrix.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            (out / "README.txt").write_text(
                "FrameGuard Visual Test Matrix\n\n"
                "The screenshots and matrix.json document browser observations. "
                "A frame element alone is not considered proof of target rendering.\n",
                encoding="utf-8"
            )

            messagebox.showinfo(APP, f"Matrix evidence saved to:\n{out}")
            self.log_line(f"Visual Test Matrix saved: {out}")
            self.status.set(f"Matrix evidence saved: {out}")
            win.grab_release()
            win.destroy()

        tree.selection_set("0")
        show_selected()

        controls = ttk.Frame(win)
        controls.pack(fill="x", padx=18, pady=(2, 14))
        ttk.Button(controls, text="View Selected Screenshot", command=view_evidence).pack(side="left")
        ttk.Button(controls, text="Close", command=lambda: (win.grab_release(), win.destroy())).pack(side="right", padx=(8, 0))
        ttk.Button(controls, text="Save Matrix Evidence", style="Accent.TButton", command=save_matrix).pack(side="right")

    def sameorigin_verify(self):
        url = self.target()
        if not url:
            return
        if sync_playwright is None:
            messagebox.showerror(APP, "Playwright is not installed.")
            return
        self.status.set("Running SAMEORIGIN verification…")
        threading.Thread(target=self._sameorigin_worker, args=(url,), daemon=True).start()

    def _sameorigin_worker(self, url):
        # Keep this focused: compare actual browser render signals for the target
        # and a hostname variant, rather than claiming a bypass from iframe existence.
        final = url
        try:
            rr = requests.get(url, timeout=TIMEOUT, allow_redirects=True, headers={"User-Agent": UA})
            final = rr.url
        except Exception:
            pass

        p = urlparse(final)
        host = p.hostname or ""
        variant_host = host[4:] if host.lower().startswith("www.") else "www." + host
        variant = f"{p.scheme}://{variant_host}{p.path or '/'}"
        if p.query:
            variant += "?" + p.query

        same = self._probe_frame(final, screenshot=False)
        variant_result = self._probe_frame(variant, screenshot=False)

        self.root.after(0, lambda: self._sameorigin_done(final, variant, same, variant_result))

    def _sameorigin_done(self, final, variant, same, vr):
        self.tree.delete(*self.tree.get_children())
        rows = [
            ("Target", final),
            ("Target framed content", "RENDERED" if same["rendered"] else "NOT CONFIRMED"),
            ("Target response", same["target_response_status"] or "unknown"),
            ("Hostname variant", variant),
            ("Variant framed content", "RENDERED" if vr["rendered"] else "NOT CONFIRMED"),
            ("Variant response", vr["target_response_status"] or "unknown"),
        ]
        for a, b in rows:
            self.tree.insert("", "end", values=(a, b))

        self.log_line("SAMEORIGIN verification complete.")
        self.log_line(f"Target render signal: {'YES' if same['rendered'] else 'NO'}")
        self.log_line(f"Hostname-variant render signal: {'YES' if vr['rendered'] else 'NO'}")
        self.log_line("No bypass is claimed from iframe presence alone.")
        self.status.set("SAMEORIGIN verification complete.")


if __name__ == "__main__":
    root = tk.Tk()
    FrameGuard(root)
    root.mainloop()
