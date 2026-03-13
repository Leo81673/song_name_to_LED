#!/usr/bin/env python3
"""Spotify 창 제목 읽기 테스트 (전광판 연결 불필요)"""

import time
from spotify_to_led import get_spotify_title

print("=== Spotify 창 제목 읽기 테스트 ===")
print("Spotify 데스크톱 앱을 실행하고 노래를 재생하세요.")
print("종료: Ctrl+C")
print()

try:
    while True:
        title = get_spotify_title()
        if title:
            print(f"[♪] {title}")
        else:
            print("[  ] Spotify 미재생 또는 미실행")
        time.sleep(3)
except KeyboardInterrupt:
    print("\n종료.")
