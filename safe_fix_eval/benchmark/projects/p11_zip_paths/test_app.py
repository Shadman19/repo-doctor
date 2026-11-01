# Toy project: reads files inside a zip archive with zipp.
import io
import zipfile

import zipp


def make_zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("docs/readme.txt", "hello")
    buffer.seek(0)
    return zipfile.ZipFile(buffer)


def test_read_text_inside_zip():
    assert (zipp.Path(make_zip()) / "docs" / "readme.txt").read_text() == "hello"


def test_list_directory():
    names = [p.name for p in (zipp.Path(make_zip()) / "docs").iterdir()]
    assert names == ["readme.txt"]
