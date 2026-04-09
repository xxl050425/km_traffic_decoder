import re
import shutil
import subprocess
import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Tuple


APP_TITLE = "键鼠流量解码工具"
PACKET_FILE_SUFFIXES = {".pcap", ".pcapng", ".cap"}
TSHARK_FALLBACK_PATHS = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


USB_KB_BASE_MAP = {
    0x04: "a",
    0x05: "b",
    0x06: "c",
    0x07: "d",
    0x08: "e",
    0x09: "f",
    0x0A: "g",
    0x0B: "h",
    0x0C: "i",
    0x0D: "j",
    0x0E: "k",
    0x0F: "l",
    0x10: "m",
    0x11: "n",
    0x12: "o",
    0x13: "p",
    0x14: "q",
    0x15: "r",
    0x16: "s",
    0x17: "t",
    0x18: "u",
    0x19: "v",
    0x1A: "w",
    0x1B: "x",
    0x1C: "y",
    0x1D: "z",
    0x1E: "1",
    0x1F: "2",
    0x20: "3",
    0x21: "4",
    0x22: "5",
    0x23: "6",
    0x24: "7",
    0x25: "8",
    0x26: "9",
    0x27: "0",
    0x28: "<ENTER>",
    0x29: "<ESC>",
    0x2A: "<BACKSPACE>",
    0x2B: "<TAB>",
    0x2C: " ",
    0x2D: "-",
    0x2E: "=",
    0x2F: "[",
    0x30: "]",
    0x31: "\\",
    0x33: ";",
    0x34: "'",
    0x35: "`",
    0x36: ",",
    0x37: ".",
    0x38: "/",
    0x39: "<CAPSLOCK>",
}

USB_KB_SHIFT_MAP = {
    "1": "!",
    "2": "@",
    "3": "#",
    "4": "$",
    "5": "%",
    "6": "^",
    "7": "&",
    "8": "*",
    "9": "(",
    "0": ")",
    "-": "_",
    "=": "+",
    "[": "{",
    "]": "}",
    "\\": "|",
    ";": ":",
    "'": "\"",
    "`": "~",
    ",": "<",
    ".": ">",
    "/": "?",
}

PS2_SET1_BASE_MAP = {
    0x02: "1",
    0x03: "2",
    0x04: "3",
    0x05: "4",
    0x06: "5",
    0x07: "6",
    0x08: "7",
    0x09: "8",
    0x0A: "9",
    0x0B: "0",
    0x0C: "-",
    0x0D: "=",
    0x0E: "<BACKSPACE>",
    0x0F: "<TAB>",
    0x10: "q",
    0x11: "w",
    0x12: "e",
    0x13: "r",
    0x14: "t",
    0x15: "y",
    0x16: "u",
    0x17: "i",
    0x18: "o",
    0x19: "p",
    0x1A: "[",
    0x1B: "]",
    0x1C: "<ENTER>",
    0x1E: "a",
    0x1F: "s",
    0x20: "d",
    0x21: "f",
    0x22: "g",
    0x23: "h",
    0x24: "j",
    0x25: "k",
    0x26: "l",
    0x27: ";",
    0x28: "'",
    0x29: "`",
    0x2B: "\\",
    0x2C: "z",
    0x2D: "x",
    0x2E: "c",
    0x2F: "v",
    0x30: "b",
    0x31: "n",
    0x32: "m",
    0x33: ",",
    0x34: ".",
    0x35: "/",
    0x39: " ",
    0x3A: "<CAPSLOCK>",
}

PS2_SET2_BASE_MAP = {
    0x16: "1",
    0x1E: "2",
    0x26: "3",
    0x25: "4",
    0x2E: "5",
    0x36: "6",
    0x3D: "7",
    0x3E: "8",
    0x46: "9",
    0x45: "0",
    0x4E: "-",
    0x55: "=",
    0x66: "<BACKSPACE>",
    0x0D: "<TAB>",
    0x15: "q",
    0x1D: "w",
    0x24: "e",
    0x2D: "r",
    0x2C: "t",
    0x35: "y",
    0x3C: "u",
    0x43: "i",
    0x44: "o",
    0x4D: "p",
    0x54: "[",
    0x5B: "]",
    0x5A: "<ENTER>",
    0x1C: "a",
    0x1B: "s",
    0x23: "d",
    0x2B: "f",
    0x34: "g",
    0x33: "h",
    0x3B: "j",
    0x42: "k",
    0x4B: "l",
    0x4C: ";",
    0x52: "'",
    0x0E: "`",
    0x5D: "\\",
    0x1A: "z",
    0x22: "x",
    0x21: "c",
    0x2A: "v",
    0x32: "b",
    0x31: "n",
    0x3A: "m",
    0x41: ",",
    0x49: ".",
    0x4A: "/",
    0x29: " ",
    0x58: "<CAPSLOCK>",
}

PS2_EXT_SET1_MAP = {
    0x48: "<UP>",
    0x50: "<DOWN>",
    0x4B: "<LEFT>",
    0x4D: "<RIGHT>",
    0x1C: "<NUM_ENTER>",
}

PS2_EXT_SET2_MAP = {
    0x75: "<UP>",
    0x72: "<DOWN>",
    0x6B: "<LEFT>",
    0x74: "<RIGHT>",
    0x5A: "<NUM_ENTER>",
}

MOUSE_BUTTONS = [
    (0x01, "Left"),
    (0x02, "Right"),
    (0x04, "Middle"),
    (0x08, "Button4"),
    (0x10, "Button5"),
]

MODE_OPTIONS = [
    "自动识别",
    "USB 键盘(8字节)",
    "USB 鼠标(4字节)",
    "USB 鼠标(8字节变体)",
    "PS/2 键盘 Set1",
    "PS/2 键盘 Set2",
    "PS/2 鼠标(3字节)",
]

HEX_BYTE_RE = re.compile(r"(?i)\b(?:0x)?([0-9a-f]{2})\b")


@dataclass
class DecodeResult:
    rebuilt_text: str
    events: List[str]
    stats: str


def extract_hex_tokens(line: str) -> List[int]:
    return [int(t, 16) for t in HEX_BYTE_RE.findall(line)]


def normalize_to_fixed_reports(lines: List[str], width: int) -> List[List[int]]:
    reports = []
    for line in lines:
        b = extract_hex_tokens(line)
        if len(b) < width:
            continue
        if len(b) == width:
            reports.append(b)
        else:
            reports.append(b[-width:])
    return reports


def flatten_hex_stream(lines: List[str]) -> List[int]:
    stream = []
    for line in lines:
        stream.extend(extract_hex_tokens(line))
    return stream


def apply_shift_caps(ch: str, shift: bool, caps_lock: bool) -> str:
    if len(ch) == 1 and "a" <= ch <= "z":
        return ch.upper() if shift ^ caps_lock else ch
    if shift and ch in USB_KB_SHIFT_MAP:
        return USB_KB_SHIFT_MAP[ch]
    return ch


def decode_usb_keyboard(lines: List[str]) -> DecodeResult:
    reports = normalize_to_fixed_reports(lines, 8)
    events = []
    output = []
    caps_lock = False
    prev_keys = set()
    decoded_count = 0

    for i, rpt in enumerate(reports, start=1):
        modifier = rpt[0]
        shift = bool(modifier & 0x22)
        keys = {k for k in rpt[2:] if k != 0}
        new_keys = [k for k in rpt[2:] if k != 0 and k not in prev_keys]

        for key in new_keys:
            decoded_count += 1
            label = USB_KB_BASE_MAP.get(key, "<UNK:0x{0:02X}>".format(key))

            if label == "<CAPSLOCK>":
                caps_lock = not caps_lock
                events.append("[{0}] CAPSLOCK -> {1}".format(i, "ON" if caps_lock else "OFF"))
                continue

            if label == "<BACKSPACE>":
                if output:
                    output.pop()
                events.append("[{0}] BACKSPACE".format(i))
                continue

            if label == "<ENTER>":
                output.append("\n")
                events.append("[{0}] ENTER".format(i))
                continue

            if label == "<TAB>":
                output.append("\t")
                events.append("[{0}] TAB".format(i))
                continue

            if len(label) == 1 or label == " ":
                actual = apply_shift_caps(label, shift, caps_lock)
                output.append(actual)
                events.append(
                    "[{0}] KEY 0x{1:02X} -> {2} (shift={3}, caps={4})".format(
                        i, key, repr(actual), int(shift), int(caps_lock)
                    )
                )
            else:
                events.append("[{0}] SPECIAL {1}".format(i, label))

        prev_keys = keys

    stats = (
        "模式: USB 键盘(8字节)\n"
        "解析到报告: {0}\n"
        "触发按键事件: {1}\n"
        "重建文本长度: {2}".format(len(reports), decoded_count, len("".join(output)))
    )
    return DecodeResult("".join(output), events, stats)


def decode_usb_mouse(lines: List[str]) -> DecodeResult:
    reports = normalize_to_fixed_reports(lines, 4)
    events = []
    pos_x = 0
    pos_y = 0
    prev_buttons = 0
    move_count = 0
    wheel_count = 0
    btn_count = 0

    def i8(v: int) -> int:
        return v - 256 if v > 127 else v

    for i, rpt in enumerate(reports, start=1):
        btn = rpt[0]
        dx = i8(rpt[1])
        dy = i8(rpt[2])
        wheel = i8(rpt[3])

        if dx or dy:
            pos_x += dx
            pos_y += dy
            move_count += 1
            events.append("[{0}] MOVE dx={1} dy={2} => pos=({3},{4})".format(i, dx, dy, pos_x, pos_y))

        if wheel:
            wheel_count += 1
            events.append("[{0}] WHEEL {1:+d}".format(i, wheel))

        changed = btn ^ prev_buttons
        if changed:
            for mask, name in MOUSE_BUTTONS:
                if changed & mask:
                    state = "DOWN" if (btn & mask) else "UP"
                    btn_count += 1
                    events.append("[{0}] {1} {2}".format(i, name, state))

        prev_buttons = btn

    stats = (
        "模式: USB 鼠标(4字节)\n"
        "解析到报告: {0}\n"
        "移动事件: {1}\n"
        "滚轮事件: {2}\n"
        "按键事件: {3}\n"
        "最终相对坐标: ({4},{5})".format(len(reports), move_count, wheel_count, btn_count, pos_x, pos_y)
    )
    rebuilt = "USB 鼠标数据无文本输出，请看事件日志。"
    return DecodeResult(rebuilt, events, stats)


def _s8(v: int) -> int:
    return v - 256 if v > 127 else v


def _s16_le(lo: int, hi: int) -> int:
    val = (hi << 8) | lo
    return val - 65536 if val >= 32768 else val


def _decode_usb_mouse8_pattern(
    reports: List[List[int]], pattern_id: int
) -> Tuple[List[str], str, int, int, int, int, int, int]:
    events = []
    pos_x = 0
    pos_y = 0
    prev_buttons = 0
    move_count = 0
    wheel_count = 0
    btn_count = 0
    spike_penalty = 0

    for i, rpt in enumerate(reports, start=1):
        if pattern_id == 1:
            btn = rpt[0]
            dx = _s16_le(rpt[2], rpt[3])
            dy = _s16_le(rpt[4], rpt[5])
            wheel = _s8(rpt[6])
        else:
            btn = rpt[0]
            dx = _s16_le(rpt[4], rpt[5])
            dy = _s16_le(rpt[2], rpt[3])
            wheel = _s8(rpt[6])

        if abs(dx) > 4096 or abs(dy) > 4096:
            spike_penalty += 3
        if abs(dx) > 2048 or abs(dy) > 2048:
            spike_penalty += 1

        if dx or dy:
            pos_x += dx
            pos_y += dy
            move_count += 1
            events.append("[{0}] MOVE dx={1} dy={2} => pos=({3},{4})".format(i, dx, dy, pos_x, pos_y))

        if wheel:
            wheel_count += 1
            events.append("[{0}] WHEEL {1:+d}".format(i, wheel))

        changed = btn ^ prev_buttons
        if changed:
            for mask, name in MOUSE_BUTTONS:
                if changed & mask:
                    state = "DOWN" if (btn & mask) else "UP"
                    btn_count += 1
                    events.append("[{0}] {1} {2}".format(i, name, state))
        prev_buttons = btn

    pattern_name = "P1(btn=b0 dx=b2-3 dy=b4-5)" if pattern_id == 1 else "P2(btn=b0 dx=b4-5 dy=b2-3)"
    score = move_count * 4 + btn_count + wheel_count - spike_penalty
    return events, pattern_name, move_count, wheel_count, btn_count, pos_x, pos_y, score


def decode_usb_mouse_8_variant(lines: List[str]) -> DecodeResult:
    reports = [extract_hex_tokens(x)[-8:] for x in lines if len(extract_hex_tokens(x)) >= 8]
    if not reports:
        return DecodeResult("USB 鼠标(8字节变体)未提取到有效报告。", [], "模式: USB 鼠标(8字节变体)\n报告数: 0")

    p1 = _decode_usb_mouse8_pattern(reports, 1)
    p2 = _decode_usb_mouse8_pattern(reports, 2)
    best = p1 if p1[-1] >= p2[-1] else p2
    events, pattern_name, move_count, wheel_count, btn_count, pos_x, pos_y, _score = best

    stats = (
        "模式: USB 鼠标(8字节变体)\n"
        "采用模式: {0}\n"
        "解析到报告: {1}\n"
        "移动事件: {2}\n"
        "滚轮事件: {3}\n"
        "按键事件: {4}\n"
        "最终相对坐标: ({5},{6})".format(
            pattern_name, len(reports), move_count, wheel_count, btn_count, pos_x, pos_y
        )
    )
    rebuilt = "USB 鼠标(8字节变体)数据无文本输出，请看事件日志与轨迹。"
    return DecodeResult(rebuilt, events, stats)


def decode_ps2_keyboard_set1(lines: List[str]) -> DecodeResult:
    stream = flatten_hex_stream(lines)
    output = []
    events = []
    pressed = set()
    caps_lock = False
    ext = False
    event_count = 0

    for i, byte in enumerate(stream, start=1):
        if byte == 0xE0:
            ext = True
            continue

        released = bool(byte & 0x80)
        code = byte & 0x7F
        key_id = (ext, code)

        if code in (0x2A, 0x36):
            if released:
                pressed.discard((False, code))
            else:
                pressed.add((False, code))
            ext = False
            continue

        if released:
            pressed.discard(key_id)
            ext = False
            continue

        if key_id in pressed:
            ext = False
            continue
        pressed.add(key_id)

        if ext:
            label = PS2_EXT_SET1_MAP.get(code, "<EXT1:0x{0:02X}>".format(code))
            events.append("[{0}] {1}".format(i, label))
            event_count += 1
            ext = False
            continue

        label = PS2_SET1_BASE_MAP.get(code, "<UNK1:0x{0:02X}>".format(code))
        shift = (False, 0x2A) in pressed or (False, 0x36) in pressed

        if label == "<CAPSLOCK>":
            caps_lock = not caps_lock
            events.append("[{0}] CAPSLOCK -> {1}".format(i, "ON" if caps_lock else "OFF"))
            event_count += 1
            ext = False
            continue
        if label == "<BACKSPACE>":
            if output:
                output.pop()
            events.append("[{0}] BACKSPACE".format(i))
            event_count += 1
            ext = False
            continue
        if label == "<ENTER>":
            output.append("\n")
            events.append("[{0}] ENTER".format(i))
            event_count += 1
            ext = False
            continue
        if label == "<TAB>":
            output.append("\t")
            events.append("[{0}] TAB".format(i))
            event_count += 1
            ext = False
            continue
        if len(label) == 1 or label == " ":
            actual = apply_shift_caps(label, shift, caps_lock)
            output.append(actual)
            events.append(
                "[{0}] 0x{1:02X} -> {2} (shift={3}, caps={4})".format(
                    i, code, repr(actual), int(shift), int(caps_lock)
                )
            )
            event_count += 1
        else:
            events.append("[{0}] {1}".format(i, label))
            event_count += 1

        ext = False

    stats = (
        "模式: PS/2 键盘 Set1\n"
        "解析字节数: {0}\n"
        "触发按键事件: {1}\n"
        "重建文本长度: {2}".format(len(stream), event_count, len("".join(output)))
    )
    return DecodeResult("".join(output), events, stats)


def decode_ps2_keyboard_set2(lines: List[str]) -> DecodeResult:
    stream = flatten_hex_stream(lines)
    output = []
    events = []
    caps_lock = False
    shift_pressed = False
    ext = False
    break_next = False
    event_count = 0

    for i, byte in enumerate(stream, start=1):
        if byte == 0xE0:
            ext = True
            continue
        if byte == 0xF0:
            break_next = True
            continue

        code = byte
        if ext:
            label = PS2_EXT_SET2_MAP.get(code, "<EXT2:0x{0:02X}>".format(code))
            if break_next:
                events.append("[{0}] {1} UP".format(i, label))
            else:
                events.append("[{0}] {1} DOWN".format(i, label))
            event_count += 1
            ext = False
            break_next = False
            continue

        if code in (0x12, 0x59):
            shift_pressed = not break_next
            events.append("[{0}] SHIFT {1}".format(i, "DOWN" if shift_pressed else "UP"))
            event_count += 1
            break_next = False
            continue

        if break_next:
            break_next = False
            continue

        label = PS2_SET2_BASE_MAP.get(code, "<UNK2:0x{0:02X}>".format(code))

        if label == "<CAPSLOCK>":
            caps_lock = not caps_lock
            events.append("[{0}] CAPSLOCK -> {1}".format(i, "ON" if caps_lock else "OFF"))
            event_count += 1
            continue
        if label == "<BACKSPACE>":
            if output:
                output.pop()
            events.append("[{0}] BACKSPACE".format(i))
            event_count += 1
            continue
        if label == "<ENTER>":
            output.append("\n")
            events.append("[{0}] ENTER".format(i))
            event_count += 1
            continue
        if label == "<TAB>":
            output.append("\t")
            events.append("[{0}] TAB".format(i))
            event_count += 1
            continue
        if len(label) == 1 or label == " ":
            actual = apply_shift_caps(label, shift_pressed, caps_lock)
            output.append(actual)
            events.append(
                "[{0}] 0x{1:02X} -> {2} (shift={3}, caps={4})".format(
                    i, code, repr(actual), int(shift_pressed), int(caps_lock)
                )
            )
            event_count += 1
        else:
            events.append("[{0}] {1}".format(i, label))
            event_count += 1

    stats = (
        "模式: PS/2 键盘 Set2\n"
        "解析字节数: {0}\n"
        "触发按键事件: {1}\n"
        "重建文本长度: {2}".format(len(stream), event_count, len("".join(output)))
    )
    return DecodeResult("".join(output), events, stats)


def decode_ps2_mouse(lines: List[str]) -> DecodeResult:
    stream = flatten_hex_stream(lines)
    events = []
    packets = []
    i = 0
    while i + 2 < len(stream):
        b0 = stream[i]
        if not (b0 & 0x08):
            i += 1
            continue
        packets.append(stream[i : i + 3])
        i += 3

    pos_x = 0
    pos_y = 0
    prev_btn = 0
    move_count = 0
    btn_count = 0

    for idx, pkt in enumerate(packets, start=1):
        b0, b1, b2 = pkt
        left = b0 & 0x01
        right = b0 & 0x02
        middle = b0 & 0x04
        btn = (1 if left else 0) | (2 if right else 0) | (4 if middle else 0)

        dx = b1 - 256 if (b0 & 0x10) else b1
        dy = b2 - 256 if (b0 & 0x20) else b2

        if dx or dy:
            pos_x += dx
            pos_y += dy
            move_count += 1
            events.append("[{0}] MOVE dx={1} dy={2} => pos=({3},{4})".format(idx, dx, dy, pos_x, pos_y))

        changed = btn ^ prev_btn
        if changed:
            for mask, name in MOUSE_BUTTONS[:3]:
                if changed & mask:
                    state = "DOWN" if (btn & mask) else "UP"
                    btn_count += 1
                    events.append("[{0}] {1} {2}".format(idx, name, state))
        prev_btn = btn

    stats = (
        "模式: PS/2 鼠标(3字节)\n"
        "解析字节数: {0}\n"
        "识别包数: {1}\n"
        "移动事件: {2}\n"
        "按键事件: {3}\n"
        "最终相对坐标: ({4},{5})".format(len(stream), len(packets), move_count, btn_count, pos_x, pos_y)
    )
    rebuilt = "PS/2 鼠标数据无文本输出，请看事件日志。"
    return DecodeResult(rebuilt, events, stats)


def auto_detect_mode(lines: List[str]) -> str:
    all_bytes = [extract_hex_tokens(l) for l in lines if extract_hex_tokens(l)]
    if not all_bytes:
        return "USB 键盘(8字节)"

    count_8 = sum(1 for x in all_bytes if len(x) >= 8)
    count_4 = sum(1 for x in all_bytes if len(x) >= 4)
    count_stream = sum(len(x) for x in all_bytes)

    flat = [b for arr in all_bytes for b in arr]
    has_f0 = flat.count(0xF0)
    has_e0 = flat.count(0xE0)

    if has_f0 > 2 or (has_e0 > 4 and count_8 < max(5, len(all_bytes) // 4)):
        return "PS/2 键盘 Set2"
    usb_guess = guess_usb_mode_from_reports(all_bytes)
    if usb_guess != "自动识别":
        return usb_guess
    if count_stream > 20:
        return "PS/2 键盘 Set1"
    return "USB 键盘(8字节)"


def run_decode(mode: str, lines: List[str]) -> DecodeResult:
    if mode == "自动识别":
        mode = auto_detect_mode(lines)
    if mode == "USB 键盘(8字节)":
        return decode_usb_keyboard(lines)
    if mode == "USB 鼠标(4字节)":
        return decode_usb_mouse(lines)
    if mode == "USB 鼠标(8字节变体)":
        return decode_usb_mouse_8_variant(lines)
    if mode == "PS/2 键盘 Set1":
        return decode_ps2_keyboard_set1(lines)
    if mode == "PS/2 键盘 Set2":
        return decode_ps2_keyboard_set2(lines)
    if mode == "PS/2 鼠标(3字节)":
        return decode_ps2_mouse(lines)
    raise ValueError("不支持的模式: {0}".format(mode))


def _visible_char(ch: str) -> str:
    if ch == " ":
        return "<SPACE>"
    if ch == "\n":
        return "<LF>"
    if ch == "\t":
        return "<TAB>"
    return ch


def build_keyboard_analysis(rebuilt_text: str, events: List[str]) -> str:
    event_blob = "\n".join(events)
    has_keyboard_signal = bool(rebuilt_text) or any(
        key in event_blob for key in ("KEY 0x", "ENTER", "BACKSPACE", "TAB", "CAPSLOCK", "SHIFT")
    )
    if not has_keyboard_signal:
        return "未检测到键盘按键事件。"

    printable_counts: Dict[str, int] = {}
    for ch in rebuilt_text:
        printable_counts[ch] = printable_counts.get(ch, 0) + 1

    special_keys = ["ENTER", "BACKSPACE", "TAB", "CAPSLOCK", "SHIFT", "ESC", "UP", "DOWN", "LEFT", "RIGHT"]
    special_counts: Dict[str, int] = {}
    for line in events:
        for key in special_keys:
            token = "] {0}".format(key)
            if token in line:
                special_counts[key] = special_counts.get(key, 0) + 1
                break

    unknown_count = sum(1 for line in events if "<UNK" in line)
    total_printable = sum(printable_counts.values())
    unique_printable = len(printable_counts)
    top_items = sorted(printable_counts.items(), key=lambda x: (-x[1], x[0]))[:25]

    lines_out = [
        "键盘按键分析",
        "文本长度: {0}".format(len(rebuilt_text)),
        "可打印字符总数: {0}".format(total_printable),
        "可打印字符去重数: {0}".format(unique_printable),
        "未知按键事件: {0}".format(unknown_count),
        "",
        "可打印字符 Top:",
    ]
    if top_items:
        for ch, cnt in top_items:
            lines_out.append("{0}: {1}".format(_visible_char(ch), cnt))
    else:
        lines_out.append("(无)")

    lines_out.extend(["", "特殊键统计:"])
    if special_counts:
        for key, cnt in sorted(special_counts.items(), key=lambda x: (-x[1], x[0])):
            lines_out.append("{0}: {1}".format(key, cnt))
    else:
        lines_out.append("(无)")
    return "\n".join(lines_out)


def extract_mouse_track_points(lines: List[str]) -> Tuple[List[Tuple[int, int]], str]:
    usb_reports: List[List[int]] = []
    usb_reports8: List[List[int]] = []
    ps2_packets: List[List[int]] = []
    for line in lines:
        b = extract_hex_tokens(line)
        if len(b) == 4:
            usb_reports.append(b)
        elif len(b) >= 8:
            usb_reports8.append(b[-8:])
        elif len(b) == 3 and (b[0] & 0x08):
            ps2_packets.append(b)

    points: List[Tuple[int, int]] = [(0, 0)]
    x = 0
    y = 0
    move_events = 0

    def i8(v: int) -> int:
        return v - 256 if v > 127 else v

    if usb_reports:
        for rpt in usb_reports:
            dx = i8(rpt[1])
            dy = i8(rpt[2])
            if dx or dy:
                x += dx
                y += dy
                points.append((x, y))
                move_events += 1
        summary = "鼠标轨迹(USB): 报告={0}, 位移事件={1}, 点数={2}".format(
            len(usb_reports), move_events, len(points)
        )
        return points, summary

    if usb_reports8:
        p1 = _decode_usb_mouse8_pattern(usb_reports8, 1)
        p2 = _decode_usb_mouse8_pattern(usb_reports8, 2)
        best = p1 if p1[-1] >= p2[-1] else p2
        events, pattern_name, _mv, _wh, _btn, _px, _py, _score = best
        x = 0
        y = 0
        points = [(0, 0)]
        move_events = 0
        move_re = re.compile(r"dx=([+-]?\d+)\s+dy=([+-]?\d+)")
        for line in events:
            m = move_re.search(line)
            if not m:
                continue
            dx = int(m.group(1))
            dy = int(m.group(2))
            x += dx
            y += dy
            points.append((x, y))
            move_events += 1
        summary = "鼠标轨迹(USB 8字节变体 {0}): 报告={1}, 位移事件={2}, 点数={3}".format(
            pattern_name, len(usb_reports8), move_events, len(points)
        )
        return points, summary

    if ps2_packets:
        for pkt in ps2_packets:
            b0, b1, b2 = pkt
            dx = b1 - 256 if (b0 & 0x10) else b1
            dy = b2 - 256 if (b0 & 0x20) else b2
            if dx or dy:
                x += dx
                y += dy
                points.append((x, y))
                move_events += 1
        summary = "鼠标轨迹(PS/2): 包={0}, 位移事件={1}, 点数={2}".format(
            len(ps2_packets), move_events, len(points)
        )
        return points, summary

    return [], "未检测到可用于轨迹恢复的鼠标报告。"


def parse_capture_field_to_bytes(field: str) -> List[int]:
    raw = field.strip()
    if not raw:
        return []

    if ":" in raw or "-" in raw or " " in raw or "0x" in raw.lower():
        return [int(x, 16) for x in re.findall(r"(?i)[0-9a-f]{2}", raw)]

    compact = re.sub(r"[^0-9a-fA-F]", "", raw)
    if len(compact) >= 2 and len(compact) % 2 == 0:
        out = []
        for i in range(0, len(compact), 2):
            out.append(int(compact[i : i + 2], 16))
        return out
    return [int(x, 16) for x in re.findall(r"(?i)[0-9a-f]{2}", raw)]


def guess_usb_mode_from_reports(reports: List[List[int]]) -> str:
    if not reports:
        return "自动识别"

    eights = [r[-8:] for r in reports if len(r) >= 8]
    if eights:
        tail_zeros = sum(1 for r in eights if r[6] == 0 and r[7] == 0)
        high_ff = sum(1 for r in eights if r[3] in (0, 0xFF) and r[5] in (0, 0xFF))
        move_like = sum(1 for r in eights if any(r[k] != 0 for k in (2, 3, 4, 5)))
        invalid_keyboard = sum(1 for r in eights for k in r[2:] if k in (0xFF, 0xFE, 0xFD))
        total_key_slots = max(1, len(eights) * 6)

        if (
            tail_zeros / len(eights) > 0.85
            and high_ff / len(eights) > 0.35
            and move_like / len(eights) > 0.25
            and invalid_keyboard / total_key_slots > 0.04
        ):
            return "USB 鼠标(8字节变体)"

    count_mouse = sum(1 for r in reports if len(r) in (3, 4))
    count_keyboard = sum(1 for r in reports if len(r) >= 8)
    if count_mouse >= max(10, count_keyboard * 2):
        return "USB 鼠标(4字节)"
    if count_keyboard >= max(10, count_mouse * 2):
        return "USB 键盘(8字节)"
    return "自动识别"


def resolve_tshark_executable() -> str:
    found = shutil.which("tshark")
    if found:
        return found

    for raw_path in TSHARK_FALLBACK_PATHS:
        p = Path(raw_path)
        if p.exists():
            return str(p)
    return ""


def extract_hid_lines_from_capture(capture_path: Path) -> Tuple[List[str], str, str]:
    if not capture_path.exists():
        raise RuntimeError("文件不存在: {0}".format(capture_path))

    tshark_exe = resolve_tshark_executable()
    if not tshark_exe:
        raise RuntimeError("未找到 tshark，请先安装 Wireshark/tshark。")

    cmd = [
        tshark_exe,
        "-r",
        str(capture_path),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-e",
        "frame.number",
        "-e",
        "usbhid.data",
        "-e",
        "usb.capdata",
    ]

    create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore",
            check=False,
            creationflags=create_no_window,
        )
    except FileNotFoundError:
        raise RuntimeError("未找到 tshark，可执行文件路径异常。")
    except OSError as exc:
        raise RuntimeError("调用 tshark 失败: {0}".format(exc))

    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
    if proc.returncode != 0 and not stdout.strip():
        raise RuntimeError("tshark 解析失败:\n{0}".format(stderr.strip() or "未知错误"))

    reports = []
    source_counts: Dict[str, int] = {"usbhid.data": 0, "usb.capdata": 0}

    for line in stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue

        fields = [
            ("usbhid.data", parts[1].strip()),
            ("usb.capdata", parts[2].strip()),
        ]
        picked = []
        picked_src = ""

        for src_name, field_value in fields:
            if not field_value:
                continue
            segments = re.split(r"[,;]", field_value)
            for seg in segments:
                b = parse_capture_field_to_bytes(seg)
                if len(b) > len(picked):
                    picked = b
                    picked_src = src_name

        if picked:
            reports.append(picked)
            source_counts[picked_src] += 1

    if not reports:
        err_text = stderr.strip()
        raise RuntimeError(
            "没有在该流量包中提取到 HID 数据（usbhid.data / usb.capdata）。\n"
            "请确认抓包包含 USB 键鼠流量。\n"
            + ("tshark 信息: {0}".format(err_text) if err_text else "")
        )

    lines = [" ".join("{0:02X}".format(x) for x in item) for item in reports]
    length_hist: Dict[int, int] = {}
    for item in reports:
        length_hist[len(item)] = length_hist.get(len(item), 0) + 1

    hist_text = ", ".join(
        "{0}字节:{1}".format(k, v) for k, v in sorted(length_hist.items(), key=lambda x: x[0])
    )
    suggested_mode = guess_usb_mode_from_reports(reports)
    summary = (
        "流量包: {0}\n"
        "提取 HID 报告数: {1}\n"
        "来源统计: usbhid.data={2}, usb.capdata={3}\n"
        "报告长度分布: {4}\n"
        "建议模式: {5}".format(
            capture_path,
            len(reports),
            source_counts["usbhid.data"],
            source_counts["usb.capdata"],
            hist_text or "无",
            suggested_mode,
        )
    )
    return lines, summary, suggested_mode


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1150x760")
        self.file_path_var = tk.StringVar()
        self.mode_var = tk.StringVar(value=MODE_OPTIONS[0])
        self.status_var = tk.StringVar(value="就绪")
        self.last_result: Optional[DecodeResult] = None
        self.last_input_lines: List[str] = []
        self.packet_summary = ""
        self._build_ui()

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)
        top.columnconfigure(1, weight=1)

        ttk.Label(top, text="输入文件:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(top, textvariable=self.file_path_var).grid(row=0, column=1, sticky=tk.EW, padx=6)
        ttk.Button(top, text="选择文件", command=self.choose_file).grid(row=0, column=2, padx=4)
        ttk.Button(top, text="加载文本", command=self.load_file_into_text).grid(row=0, column=3, padx=4)
        ttk.Button(top, text="分析流量包", command=self.analyze_packet_file).grid(row=0, column=4, padx=4)

        ttk.Label(top, text="解码模式:").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
        ttk.Combobox(
            top,
            values=MODE_OPTIONS,
            textvariable=self.mode_var,
            state="readonly",
            width=30,
        ).grid(row=1, column=1, sticky=tk.W, padx=6, pady=(8, 0))
        ttk.Button(top, text="开始解码", command=self.decode_now).grid(row=1, column=2, padx=4, pady=(8, 0))
        ttk.Button(top, text="导出结果", command=self.export_result).grid(row=1, column=3, padx=4, pady=(8, 0))

        mid = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        mid.pack(fill=tk.BOTH, expand=True)

        left = ttk.LabelFrame(mid, text="输入数据", padding=8)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
        self.input_text = tk.Text(left, wrap=tk.NONE, undo=True)
        self.input_text.pack(fill=tk.BOTH, expand=True)

        right = ttk.LabelFrame(mid, text="解码结果", padding=8)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(6, 0))

        notebook = ttk.Notebook(right)
        notebook.pack(fill=tk.BOTH, expand=True)

        tab1 = ttk.Frame(notebook)
        tab2 = ttk.Frame(notebook)
        tab3 = ttk.Frame(notebook)
        tab4 = ttk.Frame(notebook)
        tab5 = ttk.Frame(notebook)
        notebook.add(tab1, text="重建文本")
        notebook.add(tab2, text="事件日志")
        notebook.add(tab3, text="统计信息")
        notebook.add(tab4, text="按键分析")
        notebook.add(tab5, text="鼠标轨迹")

        self.output_text = tk.Text(tab1, wrap=tk.WORD)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.events_text = tk.Text(tab2, wrap=tk.NONE)
        self.events_text.pack(fill=tk.BOTH, expand=True)
        self.stats_text = tk.Text(tab3, wrap=tk.WORD)
        self.stats_text.pack(fill=tk.BOTH, expand=True)

        self.keyboard_analysis_text = tk.Text(tab4, wrap=tk.WORD)
        self.keyboard_analysis_text.pack(fill=tk.BOTH, expand=True)

        canvas_wrap = ttk.Frame(tab5)
        canvas_wrap.pack(fill=tk.BOTH, expand=True)
        self.track_canvas = tk.Canvas(canvas_wrap, bg="#111111")
        self.track_canvas.pack(fill=tk.BOTH, expand=True)
        self.track_canvas.bind("<Configure>", self._redraw_track_canvas)

        bottom = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        bottom.pack(fill=tk.X)
        ttk.Label(bottom, textvariable=self.status_var).pack(anchor=tk.W)

    def choose_file(self):
        path = filedialog.askopenfilename(
            title="选择输入文件",
            filetypes=[
                ("全部支持", "*.txt *.log *.csv *.asc *.data *.hid *.pcap *.pcapng *.cap"),
                ("流量包", "*.pcap *.pcapng *.cap"),
                ("文本/日志", "*.txt *.log *.csv *.asc *.data *.hid"),
                ("全部文件", "*.*"),
            ],
        )
        if path:
            self.file_path_var.set(path)

    def load_file_into_text(self):
        path = self.file_path_var.get().strip()
        if not path:
            messagebox.showwarning(APP_TITLE, "请先选择文件。")
            return

        suffix = Path(path).suffix.lower()
        if suffix in PACKET_FILE_SUFFIXES:
            self.analyze_packet_file(path)
            return

        try:
            raw = Path(path).read_text(encoding="utf-8", errors="ignore")
            self.packet_summary = ""
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", raw)
            self.status_var.set("已加载文本: {0}".format(path))
        except Exception as exc:
            messagebox.showerror(APP_TITLE, "加载失败:\n{0}".format(exc))

    def analyze_packet_file(self, preset_path: Optional[str] = None):
        path = preset_path or self.file_path_var.get().strip()
        if not path:
            path = filedialog.askopenfilename(
                title="选择流量包",
                filetypes=[("流量包", "*.pcap *.pcapng *.cap"), ("全部文件", "*.*")],
            )
            if not path:
                return

        p = Path(path)
        if p.suffix.lower() not in PACKET_FILE_SUFFIXES:
            messagebox.showwarning(APP_TITLE, "该文件不是 pcap/pcapng/cap，请使用“加载文本”。")
            return

        try:
            lines, summary, suggested_mode = extract_hid_lines_from_capture(p)
            self.file_path_var.set(str(p))
            self.packet_summary = summary
            self.input_text.delete("1.0", tk.END)
            self.input_text.insert("1.0", "\n".join(lines))
            if self.mode_var.get() == "自动识别":
                self.mode_var.set(suggested_mode)
            self.status_var.set("已提取 {0} 条 HID 报告，正在解码...".format(len(lines)))
            self.decode_now()
        except Exception as exc:
            messagebox.showerror(APP_TITLE, "流量包分析失败:\n{0}".format(exc))
            self.status_var.set("流量包分析失败")

    def decode_now(self):
        raw = self.input_text.get("1.0", tk.END)
        lines = [x.strip() for x in raw.splitlines() if x.strip()]
        if not lines:
            messagebox.showwarning(APP_TITLE, "没有可解码的数据。")
            return

        self.last_input_lines = lines
        mode = self.mode_var.get().strip() or MODE_OPTIONS[0]
        try:
            result = run_decode(mode, lines)
            final_stats = result.stats
            if self.packet_summary:
                final_stats = self.packet_summary + "\n\n" + result.stats

            self.last_result = DecodeResult(result.rebuilt_text, result.events, final_stats)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", self.last_result.rebuilt_text)

            self.events_text.delete("1.0", tk.END)
            self.events_text.insert("1.0", "\n".join(self.last_result.events))

            self.stats_text.delete("1.0", tk.END)
            self.stats_text.insert("1.0", self.last_result.stats)

            kb_analysis = build_keyboard_analysis(self.last_result.rebuilt_text, self.last_result.events)
            self.keyboard_analysis_text.delete("1.0", tk.END)
            self.keyboard_analysis_text.insert("1.0", kb_analysis)

            self._update_mouse_track(lines)

            self.status_var.set("解码完成")
        except Exception as exc:
            messagebox.showerror(APP_TITLE, "解码失败:\n{0}".format(exc))
            self.status_var.set("解码失败")

    def _update_mouse_track(self, lines: List[str]):
        points, summary = extract_mouse_track_points(lines)
        self._draw_track(points, summary)

    def _draw_track(self, points: List[Tuple[int, int]], summary: str):
        self.track_canvas.delete("all")
        w = max(self.track_canvas.winfo_width(), 300)
        h = max(self.track_canvas.winfo_height(), 200)

        self.track_canvas.create_text(10, 10, anchor="nw", fill="#DDDDDD", text=summary)

        if not points:
            self.track_canvas.create_text(
                w // 2,
                h // 2,
                fill="#AAAAAA",
                text="无轨迹数据",
                font=("Segoe UI", 12),
            )
            return

        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        min_x, max_x = min(xs), max(xs)
        min_y, max_y = min(ys), max(ys)
        span_x = max(max_x - min_x, 1)
        span_y = max(max_y - min_y, 1)
        pad = 30
        scale = min((w - 2 * pad) / span_x, (h - 2 * pad) / span_y)
        scale = max(scale, 0.1)

        mapped = []
        for x, y in points:
            mx = pad + (x - min_x) * scale
            my = h - pad - (y - min_y) * scale
            mapped.append((mx, my))

        if len(mapped) >= 2:
            flat = []
            for x, y in mapped:
                flat.extend((x, y))
            self.track_canvas.create_line(*flat, fill="#b741ff", width=2, smooth=True)

        sx, sy = mapped[0]
        ex, ey = mapped[-1]
        self.track_canvas.create_oval(sx - 4, sy - 4, sx + 4, sy + 4, fill="#00d26a", outline="")
        self.track_canvas.create_oval(ex - 4, ey - 4, ex + 4, ey + 4, fill="#ff6b35", outline="")
        self.track_canvas.create_text(sx + 8, sy, anchor="w", fill="#00d26a", text="Start")
        self.track_canvas.create_text(ex + 8, ey, anchor="w", fill="#ff6b35", text="End")

    def _redraw_track_canvas(self, _event):
        if self.last_input_lines:
            self._update_mouse_track(self.last_input_lines)

    def export_result(self):
        if not self.last_result:
            messagebox.showwarning(APP_TITLE, "请先解码，再导出。")
            return

        path = filedialog.asksaveasfilename(
            title="导出解码结果",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("全部文件", "*.*")],
            initialfile="decode_result.txt",
        )
        if not path:
            return

        out = [
            "==== 统计信息 ====",
            self.last_result.stats,
            "",
            "==== 重建文本 ====",
            self.last_result.rebuilt_text,
            "",
            "==== 事件日志 ====",
            "\n".join(self.last_result.events),
            "",
        ]
        try:
            Path(path).write_text("\n".join(out), encoding="utf-8")
            self.status_var.set("已导出: {0}".format(path))
            messagebox.showinfo(APP_TITLE, "导出成功:\n{0}".format(path))
        except Exception as exc:
            messagebox.showerror(APP_TITLE, "导出失败:\n{0}".format(exc))


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
