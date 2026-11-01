# Toy project: formats numbers and locale names with Babel.
from babel import Locale
from babel.numbers import format_decimal


def test_german_decimal():
    assert format_decimal(1234.5, locale="de_DE") == "1.234,5"


def test_locale_display_name():
    assert Locale("fr").get_display_name("en") == "French"
