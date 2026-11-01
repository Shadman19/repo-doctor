# Toy project: turns Python code into a list of tokens with Pygments.
from pygments.lexers import PythonLexer
from pygments.token import Keyword, Name


def tokens(code):
    return [(tok, text) for tok, text in PythonLexer().get_tokens(code) if text.strip()]


def test_def_is_keyword():
    assert tokens("def f(): pass")[0] == (Keyword, "def")


def test_function_name_token():
    assert tokens("def f(): pass")[1] == (Name.Function, "f")
