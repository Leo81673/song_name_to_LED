#!/usr/bin/env python3
"""
pcap에서 Huidu D16 프로토콜 패킷을 추출하여
HDPlayer vs Python 코드의 차이점을 분석합니다.
"""
import sys
import struct
from scapy.all import rdpcap, TCP, IP, Raw


LED_IP = "192.168.6.1"
LED_PORT = 9527

CMD_NAMES = {
    0x000B: "핸드셰이크 요청",
    0x000C: "핸드셰이크 응답",
    0x000D: "상태 확인",
    0x000E: "상태 응답",
    0x000F: "전송 시작(총크기)",
    0x0010: "전송 시작 응답",
    0x0011: "파일 목록 요청",
    0x0012: "파일 목록 응답",
    0x0013: "전송 준비",
    0x0014: "전송 준비 응답",
    0x0015: "전송 확인",
    0x0016: "전송 확인 응답",
    0x0017: "파일명 전송",
    0x0018: "파일명 응답",
    0x0019: "파일 데이터",
    0x001A: "파일 데이터 응답",
    0x001B: "파일 완료",
    0x001C: "파일 완료 응답",
    0x001D: "전체 완료",
    0x001E: "전체 완료 응답",
    0x001F: "최종 확인",
    0x0020: "최종 확인 응답",
    0x0410: "인증",
    0x0411: "인증 응답",
    0x040A: "잠금 확인",
    0x040B: "잠금 응답",
    0x0730: "초기화",
    0x0731: "초기화 응답",
}


def parse_huidu_packets(raw_data):
    """바이트 스트림에서 Huidu 패킷들을 파싱"""
    packets = []
    pos = 0
    while pos + 4 <= len(raw_data):
        length, cmd = struct.unpack_from("<HH", raw_data, pos)
        if length < 4 or length > 65535 or pos + length > len(raw_data):
            break
        payload = raw_data[pos + 4:pos + length]
        packets.append((cmd, payload))
        pos += length
    return packets


def analyze_pcap(filepath, label):
    print(f"\n{'='*60}")
    print(f"  {label}: {filepath}")
    print(f"{'='*60}")

    pkts = rdpcap(filepath)

    # TCP 스트림 재조립 (9527 포트)
    client_data = b""  # PC → LED
    server_data = b""  # LED → PC

    for pkt in pkts:
        if not (IP in pkt and TCP in pkt and Raw in pkt):
            continue
        if pkt[IP].dst == LED_IP and pkt[TCP].dport == LED_PORT:
            client_data += pkt[Raw].load
        elif pkt[IP].src == LED_IP and pkt[TCP].sport == LED_PORT:
            server_data += pkt[Raw].load

    print(f"\n클라이언트→전광판: {len(client_data)}B")
    print(f"전광판→클라이언트: {len(server_data)}B")

    client_pkts = parse_huidu_packets(client_data)
    server_pkts = parse_huidu_packets(server_data)

    # 클라이언트 패킷 시퀀스 출력
    print(f"\n--- 클라이언트 송신 패킷 ({len(client_pkts)}개) ---")
    file_names = []
    for i, (cmd, payload) in enumerate(client_pkts):
        name = CMD_NAMES.get(cmd, f"알 수 없음")
        extra = ""

        if cmd == 0x000B:
            extra = f" data={payload.hex()}"
        elif cmd == 0x0730:
            extra = f" data={payload.hex()}"
        elif cmd == 0x0410:
            extra = f" auth='{payload.decode('ascii', errors='replace')[:80]}...'"
        elif cmd == 0x000F:
            if len(payload) >= 8:
                total, zero = struct.unpack_from("<II", payload)
                extra = f" total_size={total}, zero={zero}"
            else:
                extra = f" data={payload.hex()}"
        elif cmd == 0x0015:
            extra = f" data={payload.hex()}"
        elif cmd == 0x0017:
            fname = payload.rstrip(b"\x00").decode("ascii", errors="replace")
            file_names.append(fname)
            extra = f" filename='{fname}'"
        elif cmd == 0x0019:
            extra = f" size={len(payload)}B"
            # XML인지 PNG인지 확인
            if payload[:4] == b'\x89PNG':
                extra += " [PNG]"
            elif payload[:5] == b'<?xml':
                extra += " [XML/BOO]"

        print(f"  [{i:3d}] 0x{cmd:04X} {name:20s} (payload {len(payload):5d}B){extra}")

    # 서버 응답 패킷
    print(f"\n--- 전광판 응답 패킷 ({len(server_pkts)}개) ---")
    for i, (cmd, payload) in enumerate(server_pkts):
        name = CMD_NAMES.get(cmd, f"알 수 없음")
        extra = ""
        if cmd == 0x0012:
            # 파일 목록
            files = [h for h in payload.decode("ascii", errors="replace").split("\x00") if h]
            extra = f" files={files}"
        elif payload:
            extra = f" data={payload[:32].hex()}"
        print(f"  [{i:3d}] 0x{cmd:04X} {name:20s} (payload {len(payload):5d}B){extra}")

    # 전송된 파일 요약
    if file_names:
        print(f"\n--- 전송된 파일 ---")
        for fn in file_names:
            print(f"  {fn}")

    return client_pkts, server_pkts


def main():
    files = sys.argv[1:] if len(sys.argv) > 1 else ["ok.pcapng", "260314package.pcapng"]
    all_results = []
    for f in files:
        try:
            result = analyze_pcap(f, f)
            all_results.append((f, result))
        except Exception as e:
            print(f"\n[!] {f} 분석 실패: {e}")

    if len(all_results) >= 2:
        print(f"\n{'='*60}")
        print(f"  차이점 비교")
        print(f"{'='*60}")
        for fname, (client_pkts, server_pkts) in all_results:
            cmds = [f"0x{cmd:04X}" for cmd, _ in client_pkts]
            print(f"\n{fname} 클라이언트 커맨드 시퀀스:")
            print(f"  {' → '.join(cmds)}")


if __name__ == "__main__":
    main()
