# Song Name to LED

Spotify에서 현재 재생 중인 노래 제목을 가게 LED 전광판에 실시간으로 표시하는 프로젝트.

## 현재 상태
**1단계 완료** — 전광판 프로토콜 역분석 완료, 전송 스크립트 작성됨. 가게에서 실제 테스트 필요.

## 장비 정보
| 항목 | 내용 |
|------|------|
| LED 전광판 컨트롤러 | **Huidu D16** |
| 제어 프로그램 | HDPlayer v7.10.2.0 |
| 연결 방식 | 전광판 자체 WiFi (AP 모드) — SSID: `HD-XXXXXXXX` 형태 |
| 전광판 IP | `192.168.6.1` (고정) |
| 전광판 포트 | `9527` (TCP) |
| 화면 크기 | 160 x 16 픽셀 |
| 가게 인터넷 | 공유기 WiFi (별도) |

## 프로토콜 분석 결과

pcap 캡처 분석을 통해 Huidu D16 프로토콜을 역분석함.

### 통신 구조
- **TCP** 연결, 포트 9527
- 패킷 구조: `[2B length][2B command][data...]` (Little-Endian)
- 텍스트는 **PNG 이미지**로 렌더링하여 전송 (직접 텍스트 전송 아님)
- XML(.boo 파일)로 레이아웃/표시 설정 전달

### 전송 순서
1. 핸드셰이크 (cmd 0x000B → 응답 0x000C)
2. 초기화 (cmd 0x0730)
3. 인증 정보 (cmd 0x0410) — HDPlayer 형식 모방
4. 상태 확인 (cmd 0x000D)
5. 잠금 상태 확인 (cmd 0x040A)
6. 파일 전송 시작 (cmd 0x000F) — 총 크기 전달
7. 기존 파일 목록 요청 (cmd 0x0011 → 응답 0x0012)
8. 전송 준비 (cmd 0x0013, 0x0015)
9. PNG 파일 전송 (파일명 0x0017, 데이터 0x0019, 완료 0x001B)
10. XML(.boo) 파일 전송 (같은 방식, 청크 최대 ~9000B)
11. 전송 완료 (cmd 0x001D, 0x001F)

### XML 설정 구조
- 루트: `HD_Controller_Plugin` — 디스플레이 설정 (크기, 모델 등)
- 씬: `HD_OrdinaryScene_Plugin` — 재생 모드, 시간 설정
- 프레임: `HD_Frame_Plugin` — 영역 위치/크기
- 텍스트: `HD_SingleLineText_Plugin` — 표시 효과, 속도, PNG 파일 참조

## 빠른 시작

### 필수 설치
```bash
# Python 3.x 필요
pip install Pillow
```

### 사용법
```bash
# 전광판 WiFi에 연결된 상태에서 실행
python send_to_led.py "표시할 텍스트"
python send_to_led.py "지금 재생: 노래 제목"
```

### 가게 노트북 초기 설정 (Windows PowerShell)
1. **Python 설치**: https://www.python.org/downloads/ → "Add python.exe to PATH" 반드시 체크
2. **Git 설치**: https://git-scm.com/downloads/win → 기본값으로 설치
3. PowerShell 새로 열고:
```powershell
cd C:\Users\tapes
git clone https://github.com/Leo81673/song_name_to_LED.git
cd song_name_to_LED
pip install Pillow
# 전광판 WiFi 연결 후:
python send_to_led.py "테스트 1234"
```

## 파일 설명
| 파일 | 설명 |
|------|------|
| `send_to_led.py` | LED 전광판에 텍스트를 직접 전송하는 메인 스크립트 |
| `analyze_pcap.py` | pcap 캡처 파일을 분석하는 도구 (프로토콜 역분석용) |
| `ok.pcapng` | HDPlayer → 전광판 통신 캡처 파일 (분석 완료) |
| `requirements.txt` | Python 의존성 목록 |

## 진행 단계

### 1단계: 전광판 프로토콜 분석 ✅ 완료
- Wireshark로 HDPlayer ↔ 전광판 통신 캡처
- pcap 분석으로 Huidu D16 프로토콜 역분석
- `send_to_led.py` 스크립트 작성

### 2단계: 가게에서 실제 테스트 ← 현재 단계
- 전광판 WiFi 연결 후 `send_to_led.py` 실행
- 텍스트가 정상 표시되는지 확인
- 문제 발생 시 디버깅 (패킷 비교 등)

### 3단계: Spotify 현재 재생곡 가져오기
- **방법 A (간단)**: Spotify 데스크톱 앱의 창 제목 읽기 (Python)
- **방법 B (정석)**: Spotify Web API 사용 (OAuth 인증 필요)
- 방법 A 먼저 시도

### 4단계: 자동 전송 스크립트
- 5~10초마다 Spotify 재생곡 확인
- 노래 바뀌면 → LED 전광판에 새 제목 전송
- 백그라운드 자동 실행

### 5단계: 네트워크 구성
- USB WiFi 어댑터 또는 유선랜으로 인터넷 연결 유지
- 나머지 WiFi는 전광판 전용
- 두 네트워크 동시 연결 상태에서 스크립트 실행

## 필요 장비
- USB WiFi 어댑터 (1~2만원) — 인터넷과 전광판 WiFi 동시 연결용
  - 또는 유선랜(이더넷)으로 인터넷 연결 가능하면 불필요

## 리스크 및 대안
- 프로토콜이 실제 하드웨어에서 다르게 동작할 수 있음 → Wireshark로 비교 디버깅
- 대안: HDPlayer 자동화 (pyautogui로 HDPlayer UI 자동 조작)

## 참고
- Huidu D16 프로토콜은 공식 문서가 없어 pcap 역분석으로 구현
- HDPlayer v7.10.2.0 기준으로 분석됨
- 전광판 WiFi 비밀번호는 보통 없거나 기본값 사용
