"""Test the actual single-file site and Cloudflare Pages policy, without a build."""
import base64
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.ids, self.anchors, self.scripts = set(), [], []
        self.external_scripts, self.handlers = [], []
        self.in_script = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        href = attrs.get("href") or ""
        if tag == "a" and href.startswith("#"):
            self.anchors.append(href[1:])
        self.handlers.extend(key for key in attrs if key.startswith("on"))
        if tag == "script":
            self.in_script = True
            self.scripts.append("")
            if "src" in attrs:
                self.external_scripts.append(attrs["src"])

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_script = False

    def handle_data(self, data):
        if self.in_script:
            self.scripts[-1] += data


class StaticSite(unittest.TestCase):
    def test_policy(self):
        path = ROOT / "_headers"
        self.assertTrue(path.is_file(), "Pages document root must contain _headers")
        lines = [line.strip() for line in path.read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith("#")]
        self.assertEqual(lines[0], "/*")
        headers = dict(line.split(": ", 1) for line in lines[1:])
        self.assertEqual(headers["X-Frame-Options"], "SAMEORIGIN")
        self.assertEqual(headers["Strict-Transport-Security"], "max-age=31536000")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["Referrer-Policy"], "strict-origin-when-cross-origin")
        policy = dict((p[0], p[1:]) for d in headers["Content-Security-Policy"].split(";")
                      if (p := d.split()))
        self.assertEqual(policy["frame-ancestors"], ["'self'"])
        self.assertEqual(policy["object-src"], ["'none'"])
        self.assertEqual(policy["base-uri"], ["'self'"])
        self.assertEqual(policy["default-src"], ["'self'"])
        doc = Document((ROOT / "index.html").read_text())
        self.assertEqual(len(doc.scripts), 1)
        self.assertFalse(doc.external_scripts)
        self.assertFalse(doc.handlers)
        hashes = ["'sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode() + "'"
                  for s in doc.scripts]
        self.assertEqual(policy["script-src"], hashes)
        self.assertEqual(policy["style-src"], ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"])
        self.assertEqual(policy["font-src"], ["'self'", "https://fonts.gstatic.com"])
        self.assertEqual(policy["img-src"], ["'self'", "data:"])

    def test_site_structure_and_navigation(self):
        text = (ROOT / "index.html").read_text()
        doc = Document(text)
        self.assertIn("<title>OPENTHEORY", text)
        self.assertIn('<canvas', text)
        self.assertTrue({"loader", "bg"}.issubset(doc.ids))
        self.assertGreater(len(doc.anchors), 3)
        for anchor in doc.anchors:
            if anchor:
                self.assertIn(anchor, doc.ids, "broken in-document navigation")


if __name__ == "__main__":
    unittest.main()
