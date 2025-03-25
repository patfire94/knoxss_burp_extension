# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem
from java.util import ArrayList
from java.net import URL, URLEncoder
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import threading
import re

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("KNOXSS Manual Scanner")
        callbacks.registerContextMenuFactory(self)
        print("[+] KNOXSS extension loaded")

        self.knoxss_api_key = "your api key"
        self.discord_webhook = "https://discord.com/api/webhooks/1303759274983292970/lkCKZN_sgP5oOmkI9BbmD2sdDgwFpPg1W0PhpfBucfM0BgIceMgIEjADjcPRy8aokygQ"

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu.add(JMenuItem("Send to KNOXSS", actionPerformed=lambda e: self.run_knoxss(invocation)))
        return menu

    def run_knoxss(self, invocation):
        messages = invocation.getSelectedMessages()
        if not messages:
            return
        for msg in messages:
            thread = threading.Thread(target=self.knoxss_scan, args=[msg])
            thread.start()

    def knoxss_scan(self, message):
        try:
            request_info = self._helpers.analyzeRequest(message)
            url = str(request_info.getUrl())
            method = request_info.getMethod()
            headers = request_info.getHeaders()

            # Extract the request body (if any)
            request_bytes = message.getRequest()
            body = ""
            if method == "POST":
                body_offset = request_info.getBodyOffset()
                body_bytes = request_bytes[body_offset:]
                body = self._helpers.bytesToString(body_bytes)

            print("[*] Sending to KNOXSS:", url)
            print("[*] Method:", method)
            if method == "POST":
                print("[*] Body:", body)

            # Construct request payload (adjust depending on KNOXSS API support)
            data = "target=" + URLEncoder.encode(url, "UTF-8")
            data += "&method=" + URLEncoder.encode(method, "UTF-8")
            if method == "POST":
                data += "&data=" + URLEncoder.encode(body, "UTF-8")

            conn = URL("https://api.knoxss.pro").openConnection()
            conn.setDoOutput(True)
            conn.setRequestMethod("POST")
            conn.setRequestProperty("X-API-KEY", self.knoxss_api_key)
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")

            writer = OutputStreamWriter(conn.getOutputStream())
            writer.write(data)
            writer.flush()
            writer.close()

            reader = BufferedReader(InputStreamReader(conn.getInputStream()))
            response = ""
            line = reader.readLine()
            while line:
                response += line
                line = reader.readLine()
            reader.close()

            print("[+] KNOXSS response:", response)

            match = re.search(r'"PoC":\s*"(http[^"]+)"', response)
            if match:
                poc = match.group(1)
                print("[+] PoC found:", poc)
                self.send_to_discord(url, poc)
            else:
                print("[-] No PoC found")

        except Exception as e:
            print("[-] Error during KNOXSS scan:", e)

    def send_to_discord(self, url, poc):
        try:
            msg = 'Positive PoC found for target {}: {}'.format(url, poc)
            payload = '{"content": "%s"}' % msg.replace('"', '\\"')

            conn = URL(self.discord_webhook).openConnection()
            conn.setDoOutput(True)
            conn.setRequestMethod("POST")
            conn.setRequestProperty("Content-Type", "application/json")

            writer = OutputStreamWriter(conn.getOutputStream())
            writer.write(payload)
            writer.flush()
            writer.close()

            print("[+] Notification sent to Discord")

        except Exception as e:
            print("[-] Discord error:", e)
