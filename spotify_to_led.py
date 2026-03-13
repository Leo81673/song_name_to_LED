#!/usr/bin/env python3
"""
Spotify 현재 재생곡을 LED 전광판에 자동으로 표시하는 스크립트.
Spotify 데스크톱 앱의 창 제목에서 곡 정보를 읽어옵니다.

사용법: python spotify_to_led.py
(Spotify 데스크톱 앱과 전광판 WiFi 연결 필요)
"""

import ctypes
import ctypes.wintypes
import time
import sys

from send_to_led import send_text_to_led

# === 설정 ===
CHECK_INTERVAL = 5  # 초마다 Spotify 확인


def get_spotify_title():
    """Spotify 창 제목을 읽어 현재 재생곡 정보를 반환합니다.
    재생 중이면 'Artist - Song' 형태, 아니면 None 반환."""
    EnumWindows = ctypes.windll.user32.EnumWindows
    GetWindowTextW = ctypes.windll.user32.GetWindowTextW
    GetWindowTextLengthW = ctypes.windll.user32.GetWindowTextLengthW
    GetClassNameW = ctypes.windll.user32.GetClassNameW
    IsWindowVisible = ctypes.windll.user32.IsWindowVisible

    WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.wintypes.BOOL, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)

    # 1단계: Spotify 창 핸들을 먼저 찾기 (재생 중지 시에도 "Spotify" 또는 "Spotify Premium")
    spotify_hwnd = [None]
    spotify_title = [None]

    # 알려진 제외 패턴 (Chrome 브라우저 등)
    EXCLUDE_SUFFIXES = (" - Chrome", " - Edge", " - Firefox", " - Opera", " - Brave")

    def enum_callback(hwnd, lparam):
        if not IsWindowVisible(hwnd):
            return True

        length = GetWindowTextLengthW(hwnd)
        if length == 0:
            return True

        title = ctypes.create_unicode_buffer(length + 1)
        GetWindowTextW(hwnd, title, length + 1)
        title_str = title.value

        # Spotify 앱 찾기: 미재생 시 "Spotify" 또는 "Spotify Premium"
        if title_str in ("Spotify", "Spotify Premium", "Spotify Free"):
            spotify_hwnd[0] = hwnd
            return True  # 미재생 상태

        # 재생 중이면 "Artist - Song" 형태
        # 브라우저 제목 제외
        if any(title_str.endswith(s) for s in EXCLUDE_SUFFIXES):
            return True

        # Chrome_WidgetWin 클래스 + "Artist - Song" 패턴
        class_name = ctypes.create_unicode_buffer(256)
        GetClassNameW(hwnd, class_name, 256)
        if class_name.value.startswith("Chrome_WidgetWin") and " - " in title_str:
            spotify_title[0] = title_str
            return False  # 찾음

        return True

    EnumWindows(WNDENUMPROC(enum_callback), 0)
    return spotify_title[0]


def main():
    print("=== Spotify → LED 전광판 자동 전송 ===")
    print(f"확인 간격: {CHECK_INTERVAL}초")
    print("종료: Ctrl+C")
    print()

    last_title = None

    try:
        while True:
            title = get_spotify_title()

            if title is None:
                if last_title is not None:
                    print("[*] Spotify 재생 중지 또는 앱 미실행")
                    last_title = None
            elif title != last_title:
                print(f"[♪] 새 곡 감지: {title}")
                try:
                    send_text_to_led(title)
                    last_title = title
                except Exception as e:
                    print(f"[!] 전송 실패: {e}")

            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n[*] 종료합니다.")


if __name__ == "__main__":
    main()
