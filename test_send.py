#!/usr/bin/env python3
"""LED 전광판 전송 테스트 — 각 단계의 응답을 상세히 출력합니다."""

import socket
import struct
import hashlib
import io
import uuid
from datetime import datetime
from PIL import Image, ImageDraw, ImageFont

LED_IP = "192.168.6.1"
LED_PORT = 9527
SCREEN_WIDTH = 160
SCREEN_HEIGHT = 16
DEVICE_ID = "D16-23-A454A"
TEST_TEXT = "TEST"


def make_packet(cmd, data=b""):
    length = 4 + len(data)
    return struct.pack("<HH", length, cmd) + data


def recv_packet(sock, timeout=5):
    sock.settimeout(timeout)
    try:
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


def step(name, sock, cmd, data=b"", expect=None):
    """커맨드 전송 후 응답 출력. expect가 있으면 검증."""
    print(f"\n--- {name} ---")
    pkt = make_packet(cmd, data)
    print(f"  송신: cmd=0x{cmd:04X}, payload={len(data)}B")
    sock.sendall(pkt)

    length, resp_cmd, resp_data = recv_packet(sock)
    if resp_cmd is None:
        print(f"  수신: 응답 없음 (타임아웃)")
        return False

    status = "OK" if (expect is None or resp_cmd == expect) else "MISMATCH"
    print(f"  수신: cmd=0x{resp_cmd:04X}, length={length}, data={resp_data.hex(' ') if resp_data else '(없음)'}  [{status}]")

    if expect and resp_cmd != expect:
        print(f"  ⚠ 기대: 0x{expect:04X}, 실제: 0x{resp_cmd:04X}")
        return False
    return True


def render_test_png():
    img = Image.new("RGBA", (SCREEN_WIDTH, SCREEN_HEIGHT), (0, 0, 0, 255))
    draw = ImageDraw.Draw(img)
    font = None
    for fp in ["C:/Windows/Fonts/arial.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"]:
        try:
            font = ImageFont.truetype(fp, 14)
            break
        except (OSError, IOError):
            continue
    if font is None:
        font = ImageFont.load_default()
    draw.text((40, 0), TEST_TEXT, fill=(229, 147, 161, 255), font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def main():
    print(f"=== LED 전송 테스트 ===")
    print(f"텍스트: '{TEST_TEXT}'")
    print(f"대상: {LED_IP}:{LED_PORT}")

    # PNG 렌더링
    png_data = render_test_png()
    png_md5 = hashlib.md5(png_data).hexdigest()
    png_filename = f"{png_md5}.png"
    print(f"PNG: {len(png_data)}B, {SCREEN_WIDTH}x{SCREEN_HEIGHT}px")

    # XML 생성
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
        <Attribute Name="__NAME__">{TEST_TEXT}</Attribute>
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
                <Attribute Name="ClearEffect">0</Attribute>
                <Attribute Name="ClearTime">4</Attribute>
                <Attribute Name="ColorfulTextEnable">0</Attribute>
                <Attribute Name="ColorfulTextIndex">3</Attribute>
                <Attribute Name="ColorfulTextSelect">://images/Colorful/static.png</Attribute>
                <Attribute Name="ColorfulTextSpeed">0</Attribute>
                <Attribute Name="ContentAlign">132</Attribute>
                <Attribute Name="DispEffect">30</Attribute>
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
    total_size = len(png_data) + len(xml_config)
    print(f"XML: {len(xml_config)}B, 총: {total_size}B")

    # TCP 연결
    print(f"\n연결 중: {LED_IP}:{LED_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect((LED_IP, LED_PORT))
        print("연결 성공!")

        ok = True
        ok = ok and step("1. 핸드셰이크", sock, 0x000B, b"\x09\x00\x00\x01", expect=0x000C)
        ok = ok and step("2. 초기화", sock, 0x0730, b"\x02\x00\x00\x00\x00\x00\x00\x00", expect=0x0731)

        now = datetime.now()
        auth = (
            f"Windows,HDPlayer,user,PC,"
            f"0000000000000000,0000_0000_0000_0000.,"
            f"PYTHON-LED-SENDER,"
            f"{now.strftime('%Y-%m-%d_%H:%M:%S')},"
            f"wireless_32768-192.168.6.6-00:00:00:00:00:00,,"
            f"{uuid.uuid4()},"
            f"{now.strftime('%Y/%m/%d %H:%M:%S')} "
        ).encode("ascii")
        ok = ok and step("3. 인증", sock, 0x0410, auth, expect=0x0411)
        ok = ok and step("4. 상태 확인", sock, 0x000D, expect=0x000E)
        ok = ok and step("5. 잠금 확인", sock, 0x040A, expect=0x040B)
        ok = ok and step("6. 전송 시작", sock, 0x000F, struct.pack("<II", total_size, 0), expect=0x0010)
        ok = ok and step("7a. 파일 목록", sock, 0x0011, expect=0x0012)
        ok = ok and step("7b. 파일 목록(끝)", sock, 0x0011, expect=0x0012)
        ok = ok and step("8a. 전송 준비", sock, 0x0013, expect=0x0014)
        ok = ok and step("8b. 전송 확인", sock, 0x0015, b"\x00\x00\x00\x00\x01\x00\x00\x00", expect=0x0016)

        # PNG 전송
        ok = ok and step("9a. PNG 파일명", sock, 0x0017, png_filename.encode("ascii") + b"\x00", expect=0x0018)
        ok = ok and step("9b. PNG 데이터", sock, 0x0019, png_data, expect=0x001A)
        ok = ok and step("9c. PNG 완료", sock, 0x001B, expect=0x001C)

        # XML 전송
        ok = ok and step("10a. XML 파일명", sock, 0x0017, xml_filename.encode("ascii") + b"\x00", expect=0x0018)
        ok = ok and step("10b. XML 데이터", sock, 0x0019, xml_config, expect=0x001A)
        ok = ok and step("10c. XML 완료", sock, 0x001B, expect=0x001C)

        # 완료
        ok = ok and step("11a. 전송 완료", sock, 0x001D, expect=0x001E)
        ok = ok and step("11b. 최종 확인(1)", sock, 0x001F, expect=0x0020)
        step("11c. 최종 확인(2)", sock, 0x001F)  # HDPlayer는 2번 보냄

        print(f"\n{'='*40}")
        if ok:
            print("결과: 모든 단계 성공! 전광판에 'TEST' 가 보여야 합니다.")
        else:
            print("결과: 일부 단계 실패. 위 로그에서 MISMATCH/타임아웃 확인.")

    except socket.timeout:
        print("[!] 연결 시간 초과 — 전광판 WiFi 확인")
    except ConnectionRefusedError:
        print("[!] 연결 거부됨")
    except Exception as e:
        print(f"[!] 오류: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
