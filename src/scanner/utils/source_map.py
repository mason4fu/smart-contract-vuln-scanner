"""Source map utilities: convert byte offsets to line/column numbers."""

import bisect


def build_line_map(source_text: str) -> list[int]:
    """Return list where index i = byte offset of line i+1 start.

    Example: source "ab\\ncd\\n" -> [0, 3]  (line 1 starts at byte 0, line 2 at byte 3)
    """
    encoded = source_text.encode("utf-8")
    offsets = [0]
    for i, byte in enumerate(encoded):
        if byte == ord("\n"):
            offsets.append(i + 1)
    return offsets


def offset_to_line(offset: int, line_map: list[int]) -> int:
    """Binary search line_map to convert byte offset to 1-based line number."""
    if not line_map:
        return 1
    idx = bisect.bisect_right(line_map, offset) - 1
    return max(idx + 1, 1)


def offset_to_line_col(offset: int, length: int, line_map: list[int]) -> tuple[int, int, int, int]:
    """Return (line_start, col_start, line_end, col_end) from byte offset + length."""
    if not line_map:
        return 1, 0, 1, 0

    line_start_idx = bisect.bisect_right(line_map, offset) - 1
    line_start = line_start_idx + 1
    col_start = offset - line_map[max(line_start_idx, 0)]

    end_offset = offset + max(length - 1, 0)
    line_end_idx = bisect.bisect_right(line_map, end_offset) - 1
    line_end = line_end_idx + 1
    col_end = end_offset - line_map[max(line_end_idx, 0)]

    return line_start, col_start, line_end, col_end
