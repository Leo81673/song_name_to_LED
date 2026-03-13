# CLAUDE.md — 프로젝트 컨텍스트

## 프로젝트 개요
가게 LED 전광판에 Spotify 현재 재생곡을 실시간 표시하는 프로젝트.
Huidu D16 컨트롤러의 프로토콜을 역분석하여 직접 TCP 통신으로 텍스트를 전송한다.

## 핵심 기술 정보

### Huidu D16 프로토콜
- TCP 포트 9527, IP 192.168.6.1 (전광판 AP 모드)
- 패킷 포맷: `[2B length LE][2B command LE][payload]`
- 텍스트를 PNG 이미지(160x16)로 렌더링 후 전송
- XML(.boo) 파일로 레이아웃 설정 전달
- HDPlayer v7.10.2.0의 통신을 모방

### 주요 커맨드 코드
| 커맨드 | 설명 |
|--------|------|
| 0x000B | 핸드셰이크 요청 |
| 0x000C | 핸드셰이크 응답 |
| 0x0730 | 초기화 |
| 0x0410 | 인증 정보 |
| 0x000D | 상태 확인 |
| 0x040A | 잠금 상태 확인 |
| 0x000F | 파일 전송 시작 (총 크기) |
| 0x0011 | 기존 파일 목록 요청 |
| 0x0012 | 기존 파일 목록 응답 |
| 0x0013 | 전송 준비 |
| 0x0015 | 전송 준비 확인 |
| 0x0017 | 파일명 전송 |
| 0x0019 | 파일 데이터 전송 |
| 0x001B | 파일 전송 완료 |
| 0x001D | 전체 전송 완료 |
| 0x001F | 최종 확인 |

### 화면 사양
- 160 x 16 픽셀
- RGBA PNG → 핑크색(229, 147, 161) 텍스트, 검정 배경
- 한글은 맑은 고딕(malgun.ttf) 14pt 기준

### 표시 효과 (XML 설정값)
pcap에서 추출한 원본 HDPlayer 설정:

| 설정 | 값 | 의미 |
|------|-----|------|
| DispEffect | 30 | 등장 애니메이션 (왼쪽 스크롤) |
| DispEffect | 14 | 등장 애니메이션 (다른 효과, quality 씬에서 사용) |
| ClearEffect | 0 | 사라짐 애니메이션 없음 |
| ClearEffect | 25 | 사라짐 애니메이션 있음 (quality 씬에서 사용) |
| Speed | 4 | 스크롤/애니메이션 속도 |
| HoldTime | 50 | 텍스트 정지 유지 시간 |
| PlayeTime | 30 | 씬당 재생 시간 (초) |
| PlayMode | LoopTime | 시간 기반 반복 |
| ContentAlign | 132 | 정렬 방식 |
| ColorfulTextEnable | 0 | 반짝이 효과 꺼짐 |
| SingleMode | 1 | 단일 라인 모드 |

캡처에 포함된 씬 7개: PARTY, FEEL FREE, PARTY, TAPE VIBE, less thinking, smile, quality
- 각 씬 30초 재생 후 다음 씬으로 전환
- 대부분 DispEffect=30 (왼쪽 스크롤), ClearEffect=0 (사라짐 없음)
- quality 씬만 DispEffect=14, ClearEffect=25 사용

### 네트워크 구성
- 전광판: 자체 WiFi AP (192.168.6.x 대역)
- 인터넷: 가게 공유기 WiFi (별도)
- 두 네트워크 동시 연결 필요 → USB WiFi 어댑터 or 유선랜

## 코드 구조
- `send_to_led.py` — 메인 전송 스크립트
  - `render_text_to_png()`: 텍스트 → PNG 렌더링
  - `make_packet()`: 프로토콜 패킷 생성
  - `recv_packet()`: 응답 수신
  - `send_text_to_led()`: 전체 전송 플로우
- `analyze_pcap.py` — pcap 분석 도구 (개발용)
- `ok.pcapng` — 원본 캡처 파일 (참고용)

## 개발 시 주의사항
- 전광판 테스트는 전광판 WiFi에 연결된 상태에서만 가능
- pcap 분석으로 역분석한 프로토콜이므로 실제 동작과 차이가 있을 수 있음
- 패킷 비교 디버깅 시 Wireshark 사용
- Windows 환경 (가게 노트북) 기준으로 폰트 경로 설정됨

## 테스트 결과
- 전송 성공 확인 (2026-03-13)
- 글씨 색상: 핑크색(229,147,161)으로 수정 완료
- 세로 정렬: bbox 오프셋 보정으로 수정 완료
- 효과 설정: DispEffect=30 (스크롤), ClearEffect=0 (사라짐 없음)

## 다음 할 일
1. ~~가게에서 send_to_led.py 실제 테스트~~ ✅ 완료
2. 동작 확인 후 Spotify 창 제목 읽기 기능 추가
3. 자동 전송 루프 구현
4. 네트워크 이중 연결 구성
