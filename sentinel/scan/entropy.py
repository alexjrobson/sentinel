from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from sentinel.config import ENTROPY_SAMPLE_BYTES


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def file_entropy(path: Path, max_bytes: int = ENTROPY_SAMPLE_BYTES) -> float:
    with path.open("rb") as handle:
        sample = handle.read(max_bytes)
    return shannon_entropy(sample)
