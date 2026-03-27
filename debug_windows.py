#!/usr/bin/env python3
"""열린 창 목록 출력 — Spotify 창 찾기용 디버그"""

import ctypes
import ctypes.wintypes

EnumWindows = ctypes.windll.user32.EnumWindows
GetWindowTextW = ctypes.windll.user32.GetWindowTextW
GetWindowTextLengthW = ctypes.windll.user32.GetWindowTextLengthW
GetClassNameW = ctypes.windll.user32.GetClassNameW
IsWindowVisible = ctypes.windll.user32.IsWindowVisible

WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)

print("=== 현재 열린 창 목록 ===")
print(f"{'제목':<60} {'클래스명':<40}")
print("-" * 100)

def callback(hwnd, lparam):
    if not IsWindowVisible(hwnd):
        return True
    length = GetWindowTextLengthW(hwnd)
    if length == 0:
        return True
    title = ctypes.create_unicode_buffer(length + 1)
    GetWindowTextW(hwnd, title, length + 1)
    class_name = ctypes.create_unicode_buffer(256)
    GetClassNameW(hwnd, class_name, 256)
    t = title.value
    c = class_name.value
    # Spotify 관련이면 강조
    marker = " <<<" if "spotify" in t.lower() or "spotify" in c.lower() else ""
    print(f"{t:<60} {c:<40}{marker}")
    return True

EnumWindows(WNDENUMPROC(callback), 0)
