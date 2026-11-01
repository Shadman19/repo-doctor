# Toy project: renders an HTML greeting with Jinja2.
# Note: it imports jinja2.Markup, which Jinja2 removed in version 3.1.0.
# This is a real API change, so the minimal security fix (3.1.x) breaks it.
import jinja2
from jinja2 import Markup


def greeting(name):
    template = jinja2.Environment(autoescape=True).from_string("<p>Hello {{ name }}</p>")
    return template.render(name=name)


def bold(text):
    return Markup("<b>") + text + Markup("</b>")


def test_greeting_renders():
    assert greeting("Ada") == "<p>Hello Ada</p>"


def test_greeting_escapes_html():
    assert greeting("<script>") == "<p>Hello &lt;script&gt;</p>"


def test_bold_escapes_inner_text():
    assert str(bold("<i>")) == "<b>&lt;i&gt;</b>"
