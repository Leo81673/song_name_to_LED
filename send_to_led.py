#!/usr/bin/env python3
"""
Huidu D16 LED 전광판에 텍스트를 직접 전송하는 스크립트.
pcap 캡처에서 역분석한 프로토콜을 기반으로 구현.

사용법: python3 send_to_led.py "표시할 텍스트"
"""

import socket
import struct
import hashlib
import io
import sys
import time
import uuid
from datetime import datetime

from PIL import Image, ImageDraw, ImageFont

# === 설정 ===
LED_IP = "192.168.6.1"
LED_PORT = 9527
SCREEN_WIDTH = 160
SCREEN_HEIGHT = 16
DEVICE_ID = "D16-23-A454A"


def _load_font(font_size=14):
    """시스템 폰트를 로드합니다."""
    font_paths = [
        "C:/Windows/Fonts/malgun.ttf",      # 맑은 고딕 (Windows)
        "C:/Windows/Fonts/gulim.ttc",        # 굴림
        "C:/Windows/Fonts/arial.ttf",        # Arial
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",  # Linux
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for fp in font_paths:
        try:
            return ImageFont.truetype(fp, font_size)
        except (OSError, IOError):
            continue
    return ImageFont.load_default()


def measure_text_width(text, font_size=14):
    """텍스트의 렌더링 너비(픽셀)를 측정합니다."""
    font = _load_font(font_size)
    tmp = Image.new("RGBA", (1, 1))
    draw = ImageDraw.Draw(tmp)
    bbox = draw.textbbox((0, 0), text, font=font)
    return bbox[2] - bbox[0]


def render_text_to_png(text, width=SCREEN_WIDTH, height=SCREEN_HEIGHT, font_size=14):
    """텍스트를 PNG 이미지로 렌더링합니다.
    width가 None이면 텍스트 전체 너비에 맞춰 자동 결정."""
    font = _load_font(font_size)

    # 텍스트 크기 측정
    tmp = Image.new("RGBA", (1, 1))
    tmp_draw = ImageDraw.Draw(tmp)
    bbox = tmp_draw.textbbox((0, 0), text, font=font)
    text_w = bbox[2] - bbox[0]
    text_h = bbox[3] - bbox[1]

    # 자동 너비: 텍스트 전체가 들어가는 크기
    if width is None:
        width = text_w + 4  # 약간의 여백

    img = Image.new("RGBA", (width, height), (0, 0, 0, 255))
    draw = ImageDraw.Draw(img)

    # 텍스트 배치 (bbox 오프셋 보정)
    x = max(0, (width - text_w) // 2) - bbox[0]
    y = max(0, (height - text_h) // 2) - bbox[1]

    draw.text((x, y), text, fill=(229, 147, 161, 255), font=font)

    # PNG 바이트로 변환
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_packet(cmd, data=b""):
    """Huidu 프로토콜 패킷을 생성합니다."""
    length = 4 + len(data)  # 2(length) + 2(cmd) + data
    return struct.pack("<HH", length, cmd) + data


def recv_packet(sock, timeout=5):
    """응답 패킷을 수신합니다."""
    sock.settimeout(timeout)
    try:
        # 먼저 헤더(4바이트) 수신
        header = b""
        while len(header) < 4:
            chunk = sock.recv(4 - len(header))
            if not chunk:
                return None, None, b""
            header += chunk

        length, cmd = struct.unpack("<HH", header)
        data = b""
        remaining = length - 4
        while remaining > 0:
            chunk = sock.recv(min(remaining, 4096))
            if not chunk:
                break
            data += chunk
            remaining -= len(chunk)
        return length, cmd, data
    except socket.timeout:
        return None, None, b""


def send_text_to_led(text):
    """텍스트를 LED 전광판에 전송합니다."""
    print(f"[*] 텍스트: '{text}'")

    # 텍스트 바이트 길이에 따라 효과 결정
    text_bytes = len(text.encode("utf-8"))
    use_scroll = text_bytes > 22
    if use_scroll:
        disp_effect = 30   # 왼쪽 스크롤 (우→좌)
        clear_effect = 0
        # 스크롤: 텍스트 전체 너비로 렌더링
        png_data = render_text_to_png(text, width=None)
        print(f"[*] 스크롤 모드 (텍스트 {text_bytes}B > 22B)")
    else:
        disp_effect = 14    # 정적 표시
        clear_effect = 0
        # 정적: 화면 너비에 맞춰 렌더링
        png_data = render_text_to_png(text)
        print(f"[*] 정적 모드 (텍스트 {text_bytes}B <= 22B)")

    # 1. PNG 렌더링
    png_md5 = hashlib.md5(png_data).hexdigest()
    png_filename = f"{png_md5}.png"
    print(f"[*] PNG 렌더링 완료: {len(png_data)}B, MD5: {png_md5}")

    # 2. XML 레이아웃 생성
    scene_guid = str(uuid.uuid4())
    frame_guid = str(uuid.uuid4())
    text_guid = str(uuid.uuid4())

    xml_config = f"""<?xml version="1.0" encoding="UTF-8"?>
<Node Level="1" Type="HD_Controller_Plugin">
    <Attribute Name="AppVersion">7.10.2.0</Attribute>
    <Attribute Name="DeviceModel">D16</Attribute>
    <Attribute Name="Height">{SCREEN_HEIGHT}</Attribute>
    <Attribute Name="InsertProject">0</Attribute>
    <Attribute Name="NewSpecialEffect">close</Attribute>
    <Attribute Name="Rotation">0</Attribute>
    <Attribute Name="Stretch">0</Attribute>
    <Attribute Name="SvnVersion">12673</Attribute>
    <Attribute Name="TimeZone">32400</Attribute>
    <Attribute Name="Width">{SCREEN_WIDTH}</Attribute>
    <Attribute Name="ZoomModulus">4</Attribute>
    <Attribute Name="__NAME__">디스플레이</Attribute>
    <Attribute Name="mimiScreen">0</Attribute>
    <List Name="communication" Index="0">
        <ListItem name="" id="{DEVICE_ID}"/>
    </List>
    <Node Level="2" Type="HD_OrdinaryScene_Plugin">
        <Attribute Name="Alpha">255</Attribute>
        <Attribute Name="BgColor">-16777216</Attribute>
        <Attribute Name="BgMode">BgImage</Attribute>
        <Attribute Name="Checked">2</Attribute>
        <Attribute Name="FixedDuration">30000</Attribute>
        <Attribute Name="FrameEffect">0</Attribute>
        <Attribute Name="FrameSpeed">4</Attribute>
        <Attribute Name="FrameType">0</Attribute>
        <Attribute Name="Friday">0</Attribute>
        <Attribute Name="Monday">0</Attribute>
        <Attribute Name="MotleyIndex">0</Attribute>
        <Attribute Name="PlayIndex">0</Attribute>
        <Attribute Name="PlayMode">LoopTime</Attribute>
        <Attribute Name="PlayTimes">1</Attribute>
        <Attribute Name="PlayeTime">30</Attribute>
        <Attribute Name="PurityColor">255</Attribute>
        <Attribute Name="PurityIndex">0</Attribute>
        <Attribute Name="Saturday">0</Attribute>
        <Attribute Name="SpaceStartTime">00:00:00</Attribute>
        <Attribute Name="SpaceStopTime">23:59:59</Attribute>
        <Attribute Name="Sunday">0</Attribute>
        <Attribute Name="Thursday">0</Attribute>
        <Attribute Name="TricolorIndex">0</Attribute>
        <Attribute Name="Tuesday">0</Attribute>
        <Attribute Name="UseSpacifiled">0</Attribute>
        <Attribute Name="Volume">100</Attribute>
        <Attribute Name="Wednesday">0</Attribute>
        <Attribute Name="__GUID__">{{{scene_guid}}}</Attribute>
        <Attribute Name="__NAME__">{text[:20]}</Attribute>
        <List Name="__FileList__" Index="-1"/>
        <Node Level="3" Type="HD_Frame_Plugin">
            <Attribute Name="Alpha">255</Attribute>
            <Attribute Name="ChildType">HD_SingleLineText_Plugin</Attribute>
            <Attribute Name="FrameSpeed">4</Attribute>
            <Attribute Name="FrameType">0</Attribute>
            <Attribute Name="Height">{SCREEN_HEIGHT}</Attribute>
            <Attribute Name="LockArea">0</Attribute>
            <Attribute Name="MotleyIndex">0</Attribute>
            <Attribute Name="PurityColor">255</Attribute>
            <Attribute Name="PurityIndex">0</Attribute>
            <Attribute Name="TricolorIndex">0</Attribute>
            <Attribute Name="Width">{SCREEN_WIDTH}</Attribute>
            <Attribute Name="X">0</Attribute>
            <Attribute Name="Y">0</Attribute>
            <Attribute Name="__GUID__">{{{frame_guid}}}</Attribute>
            <Attribute Name="__NAME__">한 줄의 텍스트1</Attribute>
            <Node Level="4" Type="HD_SingleLineText_Plugin">
                <Attribute Name="ByCount">1</Attribute>
                <Attribute Name="ByTime">300</Attribute>
                <Attribute Name="ClearEffect">{clear_effect}</Attribute>
                <Attribute Name="ClearTime">4</Attribute>
                <Attribute Name="ColorfulTextEnable">0</Attribute>
                <Attribute Name="ColorfulTextIndex">3</Attribute>
                <Attribute Name="ColorfulTextSelect">://images/Colorful/static.png</Attribute>
                <Attribute Name="ColorfulTextSpeed">0</Attribute>
                <Attribute Name="ContentAlign">132</Attribute>
                <Attribute Name="DispEffect">{disp_effect}</Attribute>
                <Attribute Name="DispTime">4</Attribute>
                <Attribute Name="EditBgColor">0</Attribute>
                <Attribute Name="HeadCloseToTail">1</Attribute>
                <Attribute Name="HoldTime">50</Attribute>
                <Attribute Name="Html"></Attribute>
                <Attribute Name="PageCount">1</Attribute>
                <Attribute Name="PlayType">ByCount</Attribute>
                <Attribute Name="SingleMode">1</Attribute>
                <Attribute Name="Speed">4</Attribute>
                <Attribute Name="SpeedTimeIndex">4</Attribute>
                <Attribute Name="StrokeColor">65280</Attribute>
                <Attribute Name="TransBgColor">1</Attribute>
                <Attribute Name="UseHollow">0</Attribute>
                <Attribute Name="UseStroke">0</Attribute>
                <Attribute Name="__GUID__">{{{text_guid}}}</Attribute>
                <Attribute Name="__NAME__">한 줄의 텍스트2</Attribute>
                <List Name="__FileList__" Index="-1">
                    <ListItem FileName="{png_filename}" FileKey="SingleLineText" MD5="{png_md5}"/>
                </List>
            </Node>
        </Node>
    </Node>
</Node>""".encode("utf-8")

    xml_md5 = hashlib.md5(xml_config).hexdigest()
    xml_filename = f"{xml_md5}.boo"

    # 총 전송 크기 계산
    total_size = len(png_data) + len(xml_config)

    print(f"[*] XML 설정: {len(xml_config)}B")
    print(f"[*] 총 전송 크기: {total_size}B")

    # 3. TCP 연결
    print(f"[*] {LED_IP}:{LED_PORT}에 연결 중...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((LED_IP, LED_PORT))
        print("[+] 연결 성공!")

        # Step 1: 핸드셰이크
        print("[*] 핸드셰이크...")
        sock.sendall(make_packet(0x000B, b"\x09\x00\x00\x01"))
        length, cmd, data = recv_packet(sock)
        if cmd != 0x000C:
            print(f"[!] 핸드셰이크 실패: cmd=0x{cmd:04x}" if cmd else "[!] 핸드셰이크 응답 없음")
            return False
        print("[+] 핸드셰이크 성공")

        # Step 2: 초기화
        sock.sendall(make_packet(0x0730, b"\x02\x00\x00\x00\x00\x00\x00\x00"))
        length, cmd, data = recv_packet(sock)
        print(f"[*] 초기화 응답: cmd=0x{cmd:04x}" if cmd else "[*] 초기화 응답 없음")

        # Step 3: 인증 정보 전송
        now = datetime.now()
        auth_info = (
            f"Windows,HDPlayer,user,PC,"
            f"0000000000000000,0000_0000_0000_0000.,"
            f"PYTHON-LED-SENDER,"
            f"{now.strftime('%Y-%m-%d_%H:%M:%S')},"
            f"wireless_32768-192.168.6.6-00:00:00:00:00:00,,"
            f"{uuid.uuid4()},"
            f"{now.strftime('%Y/%m/%d %H:%M:%S')} "
        ).encode("ascii")
        sock.sendall(make_packet(0x0410, auth_info))
        length, cmd, data = recv_packet(sock)
        print(f"[*] 인증 응답: cmd=0x{cmd:04x}" if cmd else "[*] 인증 응답 없음")

        # Step 4: 상태 확인
        sock.sendall(make_packet(0x000D))
        length, cmd, data = recv_packet(sock)

        # Step 5: 잠금 상태 확인
        sock.sendall(make_packet(0x040A))
        length, cmd, data = recv_packet(sock)

        # Step 6: 파일 전송 시작 (총 크기 전달)
        print(f"[*] 파일 전송 시작 (총 {total_size}B)...")
        sock.sendall(make_packet(0x000F, struct.pack("<II", total_size, 0)))
        length, cmd, data = recv_packet(sock)
        print(f"[*] 전송 시작 응답: cmd=0x{cmd:04x}" if cmd else "[*] 응답 없음")

        # Step 7: 기존 파일 목록 요청
        sock.sendall(make_packet(0x0011))
        length, cmd, data = recv_packet(sock)
        if cmd == 0x0012 and data:
            existing_files = [h for h in data.decode("ascii", errors="replace").split("\x00") if h]
            print(f"[*] 기존 파일 {len(existing_files)}개: {existing_files[:3]}...")
        else:
            existing_files = []

        # 더 이상 파일 목록이 없을 때까지 수신
        sock.sendall(make_packet(0x0011))
        recv_packet(sock)

        # Step 8: 전송 준비
        sock.sendall(make_packet(0x0013))
        recv_packet(sock)

        sock.sendall(make_packet(0x0015, b"\x00\x00\x00\x00"))
        recv_packet(sock)

        # Step 9: PNG 파일 전송
        print(f"[*] PNG 전송 중: {png_filename}...")
        # 파일명 전송
        sock.sendall(make_packet(0x0017, png_filename.encode("ascii") + b"\x00"))
        recv_packet(sock)

        # 파일 데이터 전송
        sock.sendall(make_packet(0x0019, png_data))
        recv_packet(sock)

        # 파일 완료
        sock.sendall(make_packet(0x001B))
        recv_packet(sock)
        print("[+] PNG 전송 완료")

        # Step 10: XML(.boo) 파일 전송
        print(f"[*] XML 설정 전송 중: {xml_filename}...")
        sock.sendall(make_packet(0x0017, xml_filename.encode("ascii") + b"\x00"))
        recv_packet(sock)

        # XML 데이터는 청크로 나눠서 전송 (최대 ~9000B)
        chunk_size = 9000
        for offset in range(0, len(xml_config), chunk_size):
            chunk = xml_config[offset:offset + chunk_size]
            sock.sendall(make_packet(0x0019, chunk))
            recv_packet(sock)

        sock.sendall(make_packet(0x001B))
        recv_packet(sock)
        print("[+] XML 설정 전송 완료")

        # Step 11: 전송 완료
        sock.sendall(make_packet(0x001D))
        recv_packet(sock)

        sock.sendall(make_packet(0x001F))
        recv_packet(sock)

        print("[+] 전광판 업데이트 완료!")
        return True

    except socket.timeout:
        print("[!] 연결 시간 초과 — 전광판 WiFi에 연결되어 있는지 확인하세요")
        return False
    except ConnectionRefusedError:
        print("[!] 연결 거부됨 — IP/포트를 확인하세요")
        return False
    except Exception as e:
        print(f"[!] 오류: {e}")
        return False
    finally:
        sock.close()


def main():
    if len(sys.argv) < 2:
        print("사용법: python3 send_to_led.py \"표시할 텍스트\"")
        print()
        print("예시:")
        print("  python3 send_to_led.py \"Hello World\"")
        print("  python3 send_to_led.py \"지금 재생: 노래 제목\"")
        print()
        print(f"설정: LED IP={LED_IP}, 포트={LED_PORT}, 화면={SCREEN_WIDTH}x{SCREEN_HEIGHT}")
        sys.exit(1)

    text = sys.argv[1]
    send_text_to_led(text)


if __name__ == "__main__":
    main()
