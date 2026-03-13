#!/usr/bin/env python3
"""
LED 전광판 프로토콜 분석 스크립트
Wireshark에서 캡처한 .pcap 파일을 분석하여
전광판 컨트롤러의 IP, 포트, 프로토콜 정보를 추출합니다.
"""

import sys
import os
from collections import Counter, defaultdict
from scapy.all import rdpcap, TCP, UDP, IP, Raw


def analyze_pcap(filepath):
    """pcap 파일을 분석하여 프로토콜 정보를 출력합니다."""
    if not os.path.exists(filepath):
        print(f"[오류] 파일을 찾을 수 없습니다: {filepath}")
        sys.exit(1)

    print(f"=== LED 전광판 프로토콜 분석 ===")
    print(f"파일: {filepath}")
    print()

    packets = rdpcap(filepath)
    print(f"총 패킷 수: {len(packets)}")
    print()

    # --- 1. IP 통신 쌍 분석 ---
    ip_pairs = Counter()
    ip_packet_sizes = defaultdict(list)
    for pkt in packets:
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            pair = (src, dst)
            ip_pairs[pair] += 1
            ip_packet_sizes[pair].append(len(pkt))

    print("--- IP 통신 쌍 (상위 10개) ---")
    for (src, dst), count in ip_pairs.most_common(10):
        sizes = ip_packet_sizes[(src, dst)]
        avg_size = sum(sizes) // len(sizes)
        print(f"  {src} → {dst}: {count}패킷 (평균 {avg_size}바이트)")
    print()

    # --- 2. 포트 분석 ---
    tcp_ports = Counter()
    udp_ports = Counter()
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            tcp_ports[(pkt[IP].dst, pkt[TCP].dport)] += 1
        if UDP in pkt and IP in pkt:
            udp_ports[(pkt[IP].dst, pkt[UDP].dport)] += 1

    if tcp_ports:
        print("--- TCP 목적지 포트 (상위 10개) ---")
        for (dst, port), count in tcp_ports.most_common(10):
            print(f"  {dst}:{port} — {count}패킷")
        print()

    if udp_ports:
        print("--- UDP 목적지 포트 (상위 10개) ---")
        for (dst, port), count in udp_ports.most_common(10):
            print(f"  {dst}:{port} — {count}패킷")
        print()

    # --- 3. 페이로드가 있는 패킷 상세 분석 ---
    print("--- 페이로드 포함 패킷 (데이터 전송) ---")
    data_packets = []
    for i, pkt in enumerate(packets):
        if Raw in pkt and IP in pkt:
            raw = pkt[Raw].load
            if len(raw) > 0:
                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "OTHER"
                src = pkt[IP].src
                dst = pkt[IP].dst
                sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
                dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
                data_packets.append({
                    "index": i,
                    "proto": proto,
                    "src": src,
                    "dst": dst,
                    "sport": sport,
                    "dport": dport,
                    "data": raw,
                    "size": len(raw),
                })

    print(f"  총 {len(data_packets)}개 패킷에 페이로드 존재")
    print()

    # 가장 많은 데이터를 보낸 목적지 찾기
    dst_data = defaultdict(int)
    for dp in data_packets:
        dst_data[(dp["dst"], dp["dport"])] += dp["size"]

    if dst_data:
        print("--- 데이터 전송량 기준 상위 목적지 ---")
        for (dst, port), total in sorted(dst_data.items(), key=lambda x: -x[1])[:5]:
            print(f"  {dst}:{port} — 총 {total}바이트")
        print()

    # --- 4. 페이로드 샘플 출력 ---
    if data_packets:
        print("--- 페이로드 샘플 (처음 20개 패킷) ---")
        for dp in data_packets[:20]:
            data_hex = dp["data"][:64].hex(" ")
            data_ascii = dp["data"][:64].decode("ascii", errors="replace")
            # 비출력 문자를 점으로 대체
            data_ascii = "".join(c if 32 <= ord(c) < 127 else "." for c in data_ascii)
            print(f"  [{dp['index']:4d}] {dp['proto']} {dp['src']}:{dp['sport']} → "
                  f"{dp['dst']}:{dp['dport']} ({dp['size']}B)")
            print(f"         HEX: {data_hex}")
            print(f"         ASCII: {data_ascii}")
            print()

    # --- 5. Huidu 프로토콜 시그니처 탐색 ---
    print("--- Huidu 프로토콜 시그니처 탐색 ---")
    huidu_signatures = [
        b"\x68\x64",      # "hd" — Huidu 패킷 시작 가능성
        b"\x48\x44",      # "HD"
        b"\x55\xaa",      # 일반적인 LED 컨트롤러 매직 바이트
        b"\xaa\x55",      # 역순
        b"\x10\x00",      # Huidu 알려진 헤더
    ]
    for sig in huidu_signatures:
        matches = []
        for dp in data_packets:
            if sig in dp["data"]:
                matches.append(dp)
        if matches:
            sig_hex = sig.hex(" ")
            print(f"  시그니처 0x{sig.hex()} 발견! ({len(matches)}개 패킷)")
            for m in matches[:3]:
                print(f"    [{m['index']}] {m['src']}:{m['sport']} → {m['dst']}:{m['dport']}")
            print()

    # --- 6. 추정 결과 ---
    print("=" * 50)
    print("=== 추정 결과 ===")
    if dst_data:
        top_dst, top_port = max(dst_data, key=dst_data.get)
        print(f"  전광판 추정 IP: {top_dst}")
        print(f"  전광판 추정 포트: {top_port}")
        # 해당 목적지의 프로토콜 확인
        protos = set()
        for dp in data_packets:
            if dp["dst"] == top_dst and dp["dport"] == top_port:
                protos.add(dp["proto"])
        print(f"  프로토콜: {', '.join(protos)}")
    print()
    print("다음 단계: 이 정보를 바탕으로 Python에서 직접 전광판에 데이터를 전송하는 코드를 작성합니다.")


def main():
    if len(sys.argv) < 2:
        print("사용법: python3 analyze_pcap.py <캡처파일.pcap>")
        print()
        print("예시: python3 analyze_pcap.py capture.pcap")
        sys.exit(1)

    analyze_pcap(sys.argv[1])


if __name__ == "__main__":
    main()
