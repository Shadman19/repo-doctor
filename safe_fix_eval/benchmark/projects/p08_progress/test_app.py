# Toy project: sums numbers while showing a progress bar.
import io

from tqdm import tqdm


def total_with_progress(numbers):
    return sum(tqdm(numbers, file=io.StringIO()))


def test_total():
    assert total_with_progress([1, 2, 3]) == 6


def test_format_meter():
    assert "5/10" in tqdm.format_meter(5, 10, 1.0)
