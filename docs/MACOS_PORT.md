# FreeGSM — macOS 포팅 설계서

> **개선 추가 (2026-06-30):** 아래 세 항목을 보강했다. 단위 테스트는 통과했고,
> 실제 utun/네트워크 전환 라이브 검증은 별도로 필요하다.
> 1. **하드코딩 DNS 커버** — SOCKS5 **UDP ASSOCIATE** 구현. DPI on이면 utun으로
>    들어온 UDP/53(앱이 직접 `8.8.8.8:53` 등에 말하는 질의)을 DoH로 올린다.
>    QUIC(UDP/443)은 drop(보호 유지), 그 외 UDP는 실서버로 NAT 릴레이. ([2.1절](#21-하드코딩-dns-커버--udp-associate))
> 2. **IPv6 SNI 우회** — v6 default가 있으면 IPv6도 utun으로 redirect(`::/1`+`8000::/1`),
>    v6 SNI도 분할. `FREEGSM_TUNNEL_IPV6=0`로 끔. ([3.1절](#31-ipv6-우회))
> 3. **네트워크 변경 견고성** — `netmonitor`가 default route 변화를 폴링해 ifscope/
>    DoH 제외 라우트 재적용 + SOCKS upstream 재핀 + DNS 재포인트. ([4.1절](#41-네트워크-변경-견고성-netmonitor))
>
> **추가 보강 (2026-06-30, 2차):**
> 4. **세션 중 IPv6 획득/상실 반영** — `netmonitor`가 v6 default 출현 시
>    `tunnel._enable_v6_device`(utun v6 주소 + `::/1`/`8000::/1`), 소실 시
>    `_disable_v6_device`를 호출해 재시작 없이 v6 우회를 올리고 내린다.
> 5. **DPI-off 평문 DNS kill switch (opt-in)** — `FREEGSM_BLOCK_PLAINTEXT_DNS=1`이면
>    `macos/pf_control.py`가 pf로 비루프백 :53을 drop(fail-closed). 기본 off.
> 6. **단위 테스트** — `tests/`(stdlib unittest). `python -m unittest discover -s
>    tests`. tunnel v6 수명주기·pf kill switch·netmonitor 트리거·DPI 분할·DNS 유틸
>    커버. (이 작업 중 `socks_proxy._parse_dst`의 truncated-addr `OSError` 미처리
>    버그를 발견·수정.)
>
> **추가 보강 (2026-07-01, 3차):**
> 7. **TTL-aware DNS 캐시** — `dohproxy/dnscache.py`. `doh.resolve` 앞단의 인메모리
>    캐시로 반복 질의를 메모리에서 응답(질의 ID·0x20 케이스 재작성, RR TTL을 경과
>    시간만큼 감산). 질문(qname/qtype/qclass + EDNS DO 비트) 기준 키. 파싱 이상 시
>    무캐시 `doh.resolve`로 폴백(fail-closed 유지). macOS 리졸버 + SOCKS UDP/53만
>    사용(Windows 핸들러는 그대로 직접 호출). `FREEGSM_DNS_CACHE=0`로 끔. ([2.2절](#22-dns-캐시))
> 8. **이벤트 구동 netmonitor** — `PF_ROUTE`(`AF_ROUTE`) 커널 라우팅 소켓을 읽어
>    라우트 변화를 1초 미만에 반영. `MONITOR_INTERVAL`(10s)은 라우트 메시지로 못
>    잡는 drift(DHCP 갱신 DNS 변경 등)용 *바닥값*으로만 남김. 소켓 못 열면 폴링
>    폴백. ([4.1절](#41-네트워크-변경-견고성-netmonitor))
> 9. **라이브 검증 하니스** — `./verify_macos.sh`(status/doh/cache/sni/ipv6/
>    netchange/killswitch/vpn). 상태 읽기 + `dig` 프로브만(시스템 무변경).
>    netchange·vpn은 가이드형(사용자가 링크/VPN 전환, 스크립트가 재적용 확인).
>    단위 테스트가 닿지 못하는 실 utun/네트워크 경로 검증용. ([5절](#5-배포--패키징))
>
> **추가 보강 (2026-07-01, 4차):**
> 10. **DPI-off QUIC kill switch (opt-in)** — `FREEGSM_BLOCK_PLAINTEXT_QUIC=1`이면
>    `pf_control`이 비루프백 UDP/443을 drop → HTTP/3가 TCP/443로 폴백. TCP/443은
>    절대 막지 않음(전체 HTTPS 보호). SNI를 숨기진 못하고(터널 없으면 불가) QUIC를
>    통째로 막는 망에서 TCP 강제 + fail-closed 일관성이 목적. 기본 off. ([2.1절](#21-하드코딩-dns-커버--udp-associate))
> 11. **DNS 캐시 Windows 이식** — `dnscache`가 이제 양 플랫폼 공용. Windows
>    `udp_handler`/`tcp_proxy`도 `doh.resolve` 대신 `dnscache.resolve` 호출(반복
>    질의 메모리 히트, DoH 부하 감소). fail-closed·stateless 불변식 그대로. ([2.2절](#22-dns-캐시))
> 12. **VPN 공존 견고화** — 풀터널 VPN이 조용히 FreeGSM을 무력화하는 두 경우를
>    `netmonitor`가 *감지·경고*(자동 대응 안 함 — VPN 라우트/리졸버와 싸우면 DNS를
>    브릭할 위험): (a) VPN이 configd로 DNS를 설정해 유효 primary 리졸버가
>    `127.0.0.1`이 아니게 되면 `dns_control.verify_primary_resolver`(`scutil --dns`)가
>    DoH 우회 경고, (b) VPN이 같은 `0/1`+`128/1` 트릭으로 디바이스 라우트를 뺏으면
>    `tunnel.device_routes_intact`(`netstat -rn`)가 SNI 분할 우회 경고. `verify_macos.sh vpn`이 둘 다 확인. ([6절](#6-알려진-차이--한계-windows-대비))
>
> **상태: 구현 완료 · 라이브 검증됨 (2026-06-26, macOS 26.5.1).**
> macOS 포팅은 Windows의 WinDivert 패킷 캡처 모델을 쓰지 않는다. pf `rdr`로 같은
> 모델을 재현하려던 1차 시도(아래 [부록 A](#부록-a--폐기된-pf-rdr-설계기록))는
> **실패**했고, 대신 OS 표준 메커니즘 두 가지로 두 작업을 따로 구현했다:
>
> | 작업 | macOS 방식 | 모듈 |
> |------|-----------|------|
> | **DoH** | 로컬 DoH 리졸버를 띄우고 **시스템 DNS를 `127.0.0.1`로 스왑**, 종료 시 원복 | `macos/resolver.py`, `macos/dns_control.py` |
> | **SNI/443** | **utun + tun2socks**로 아웃바운드 TCP를 로컬 **SOCKS5 분할 프록시**로 흘려보냄 | `macos/tunnel.py`, `macos/socks_proxy.py` |
>
> 엔트리포인트: `sudo python -m dohproxy.macos.main` (DoH + DPI 동시).
> 폐기된 pf 설계는 기록 목적으로 [부록 A](#부록-a--폐기된-pf-rdr-설계기록)에 보존한다.

---

## 1. 왜 Windows 모델이 안 맞나

FreeGSM의 절반(DoH 클라이언트 · TLS 레코드 분할 · 로컬 서버 로직)은 OS와 무관한
순수 Python이라 그대로 넘어간다. 문제는 나머지 절반인 **패킷 가로채기 엔진**이다.

- Windows는 WinDivert(커널 드라이버)로 *모든* 아웃바운드 UDP/53·TCP/53·TCP/443을
  캡처해 사용자공간에서 재주입한다. macOS에는 동등물이 없다.
- macOS pf의 `rdr`은 **인터페이스로 들어오는(inbound)** 패킷에만 적용되고, 이 호스트가
  스스로 만들어내는 아웃바운드 연결(=가로채려는 대상)에는 매칭되지 않는다. Linux
  `iptables OUTPUT REDIRECT` 대응물이 macOS pf엔 없고 `divert-to`도 없다 →
  [부록 A](#부록-a--폐기된-pf-rdr-설계기록)에서 스파이크로 확인.

그래서 두 작업을 **서로 다른 표준 메커니즘**으로 분리 구현한다. DoH는 시스템
리졸버를 재설정, SNI/443은 utun 미니 VPN. DNS는 utun에 태우지 않고 분리 유지한다
(엉킴 방지).

### 그대로 넘어온 모듈 (플랫폼 무관)

| 파일 | 비고 |
|------|------|
| `dohproxy/doh.py` | httpx HTTP/2 DoH 클라이언트. **그대로**. |
| `dohproxy/dpi.py` | `split_hello` / `sni_name`, I/O 없는 순수 TLS. **그대로**. |
| `dohproxy/dnsutil.py` | 로깅용. **그대로**. |
| `dohproxy/config.py` | DoH 상수 유지. macOS 상수 추가(`LOCAL_DNS_HOST/PORT`, `DPI_BYPASS` 등). |

---

## 2. DoH — 시스템 DNS 스왑 방식

**핵심 아이디어**: 패킷을 가로채지 않는다. 로컬에 DoH 리졸버를 띄우고 **시스템
DNS 서버를 `127.0.0.1`로 바꾼 뒤, 종료 시 원래 값으로 복원**한다. 표준 DNS
질의가 로컬 리졸버로 들어오면 그대로 DoH로 중계한다 (RFC 8484: DNS wire 포맷 ==
DoH 본문, 그래서 `doh.resolve(query_bytes)`를 그대로 쓸 수 있음).

```
앱(브라우저 등) --DNS--> 127.0.0.1:53 (로컬 리졸버) --DoH/HTTP2--> 1.0.0.1
                            ↑ 시스템 DNS를 여기로 재설정 (종료 시 원복)
```

### 모듈

| 파일 | 처리 |
|------|------|
| `dohproxy/macos/resolver.py` | `127.0.0.1:53` UDP+TCP 리졸버. UDP는 `recvfrom→doh.resolve→sendto`; TCP는 length-prefixed DoH 종단. |
| `dohproxy/macos/dns_control.py` | 활성 네트워크 서비스들의 현재 DNS 백업 → `127.0.0.1`로 설정 → 종료 시 복원 + 캐시 flush. |

### dns_control.py 동작

```bash
# 활성 서비스 열거 → 각 서비스의 현재 DNS 백업 → 127.0.0.1로 변경
networksetup -listallnetworkservices
networksetup -getdnsservers "<service>"      # 백업 (없으면 "empty"로 기록)
networksetup -setdnsservers "<service>" 127.0.0.1
# 복원 (종료 시): 원래 서버들로, 없었으면:
networksetup -setdnsservers "<service>" empty
# 캐시 flush (스왑 직후 + 복원 후):
dscacheutil -flushcache ; killall -HUP mDNSResponder
```

### 안전 / 불변식

- **스왑 전에 upstream probe** (`doh.probe()`). 깨진 리졸버로 DNS를 돌리면 전체
  DNS가 죽으므로, fail-closed 거부 로직을 유지한다 — "거부 = DNS 스왑 안 함".
- **어떤 경로로 종료되든 DNS 복원 보장**: `try/finally` + `signal`(SIGINT/SIGTERM/
  SIGHUP) + `atexit`. 크래시로 시스템 DNS가 `127.0.0.1`에 묶인 채 리졸버가 죽으면
  사용자 DNS가 전부 막히므로 이게 최우선 불변식이다 ([main.py](../dohproxy/macos/main.py#L97-L117)의
  `_teardown` — 각 단계가 격리·idempotent).
- **비정상 종료 잔재 복구**: 시작 시 시스템 DNS가 이미 `127.0.0.1`이면 이전 실행이
  복원에 실패한 것 → 백업 파일이 있으면 그걸로 먼저 복원 시도. (백업을 디스크에
  저장하는 이유)
- **fail-closed 유지**: 로컬 리졸버가 DoH 실패 시 응답 안 보냄(평문 누출 없음).
- `127.0.0.1:53` 바인딩은 root 필요 — 기존 모델과 동일하게 root로 실행.

### "시스템 설정 안 건드림" 원칙과의 타협

Windows판은 어떤 설정도 안 바꿨지만, macOS DoH는 **DNS 서버 한 항목을 변경 후
복원**한다. 완전 무수정은 아니지만, 종료 시 원복되고 macOS에서 가장 표준적·안정적인
방법이다. (무수정을 고수하려면 결국 Network Extension으로 가야 하므로 1차 범위에서
의식적으로 타협.)

### 검증 (DoH)

```bash
sudo python -m dohproxy.macos.main      # 기동
dig example.com                          # UDP 경로 (시스템 DNS 경유)
dig +tcp example.com                     # TCP 경로
scutil --dns | grep nameserver           # 127.0.0.1 확인
# Ctrl+C 후:
networksetup -getdnsservers Wi-Fi        # 원래 값으로 복원됐는지 확인
```

> **검증됨**: 비특권 포트(5354)·root(:53) 둘 다 `dig` / `dig +tcp` 실제 DoH 해석
> 성공(example.com → HTTP/2 200 → A 레코드). 비-root 실행은 시스템을 건드리지 않고
> 거부(exit 1). root 실행 시 DNS 스왑/복원도 라이브 확인.
>
> **VPN 주의**: VPN은 자체 스코프 리졸버(utun)로 DNS를 처리할 수 있어
> `networksetup -setdnsservers`로 건 값이 VPN 활성 시 무시·충돌할 수 있다. VPN
> 사용 환경 동작은 별도 검증 필요.

---

### 2.1 하드코딩 DNS 커버 — UDP ASSOCIATE

시스템 DNS 스왑은 *시스템 리졸버를 쓰는 앱*만 커버한다. 평문 DNS 서버에 직접
말하는 앱(`8.8.8.8:53` 하드코딩)은 빠져나간다. **DPI on일 때만** 이를 막을 수
있다: default route override(0/1+128/1)는 UDP에도 적용되므로 그 UDP/53도 utun으로
들어오고, tun2socks가 SOCKS5 **UDP ASSOCIATE**로 프록시에 넘긴다. 기존 프록시는
CONNECT만 구현해 그 데이터그램을 못 흘려 *깨졌었다* — 이제 UDP ASSOCIATE를 구현.

`socks_proxy._udp_associate`의 분기:

| 대상 | 처리 |
|------|------|
| **UDP/53** | 페이로드를 DNS 질의로 보고 `doh.resolve` → DoH 응답을 원 목적지(예 `8.8.8.8:53`) 헤더로 감싸 회신. fail-closed(실패 시 무응답). 오버사이즈 응답은 TC=1로 잘라 TCP 재시도 유도(리졸버와 동일). |
| **UDP/443 (QUIC)** | `BLOCK_QUIC`(기본 on)이면 **drop** → HTTP/3가 분할되는 TCP/443로 폴백(QUIC SNI 노출 방지). |
| **그 외 UDP** | 실서버로 NAT 릴레이(per-(host,port) 업스트림 소켓, `IP_BOUND_IF`로 utun 우회, `UDP_RELAY_IDLE`초 후 회수). NTP/게임 등 호환성 확보. |

association은 tun2socks의 TCP 제어 연결 수명과 묶이고(RFC 1928), `selectors`로
제어 conn·클라이언트 소켓·업스트림 소켓을 한 스레드에서 다중화한다. UDP/53 DoH
왕복만 블로킹이라 짧은 데몬 스레드 + `BoundedSemaphore`로 분리(리졸버와 동일).

> **DPI off 보완(opt-in)**: 터널이 없으면 하드코딩 DNS를 *업그레이드*할 수 없다(pf
> `rdr`은 로컬 발신 미가로채기). 대신 `FREEGSM_BLOCK_PLAINTEXT_DNS=1`이면
> `macos/pf_control.py`가 pf 필터로 비루프백 :53 아웃바운드를 **drop**(fail-closed)
> 해 평문 누수를 막는다. 특정 외부 DNS에 의존하는 앱을 끊을 수 있어 기본 off.
> 로컬 SOCKS5는 여기서도 association당 단일 클라이언트만 가정.
>
> **DPI off QUIC(opt-in)**: 같은 `pf_control`이 `FREEGSM_BLOCK_PLAINTEXT_QUIC=1`이면
> 비루프백 **UDP/443(QUIC)**도 drop → HTTP/3가 TCP/443로 폴백한다. **TCP/443은 절대
> 막지 않는다**(막으면 전체 HTTPS·DoH가 죽는다). 터널이 없으니 SNI를 숨기진 못하고,
> QUIC를 통째로 차단·스로틀하는 망에서 TCP를 강제하고 fail-closed 일관성을 지키는
> 것이 목적. 기본 off. DPI on이면 SOCKS가 이미 drop하므로 상호배타(pf 미사용).

---

### 2.2 DNS 캐시

`doh.resolve`는 의도적으로 stateless다(질의 바이트 == DoH 본문, 파싱 0). 대신
`dohproxy/dnscache.py`가 그 앞단에 **옵트아웃 가능한 인메모리 캐시**를 둔다(기본 on,
`FREEGSM_DNS_CACHE=0`로 끔). stateless 불변식은 그대로 둔 채, 별도 모듈에서 필요한
만큼만 와이어 포맷을 파싱하고 **어떤 이상이든 무캐시 `doh.resolve`로 폴백**한다 — 즉
캐시는 네트워크 왕복을 메모리 히트로 바꿀 뿐, 답을 만들거나 망가뜨릴 수 없다(fail-closed
유지).

| 항목 | 처리 |
|------|------|
| **키** | 질문 = 소문자 QNAME + QTYPE + QCLASS + EDNS **DO 비트**. txn ID·0x20 케이스·EDNS 패딩만 다른 질의는 한 엔트리를 공유. |
| **히트** | 캐시 응답을 새 질의의 ID로, 질문 바이트를 새 질의의 0x20 케이스로 재작성하고, 모든 RR TTL을 **저장 후 경과 초만큼 감산**(클라이언트가 멈춘 TTL을 보지 않음). |
| **저장 대상** | 단일 질문·표준 질의(opcode 0)·비잘림 NOERROR/NXDOMAIN·양수 최소 TTL만. 음수 응답은 SOA MINIMUM으로 캡(RFC 2308). |
| **경계** | `DNS_CACHE_MAX`(4096) 초과 시 만료분 먼저, 그다음 오래된 것부터 evict. `DNS_CACHE_MAX_TTL`(86400s)로 단일 엔트리 수명 상한. |

리졸버(UDP/TCP)와 SOCKS UDP/53(하드코딩 DNS) 경로가 같은 프로세스 캐시를 공유한다.
라이브 검증: example.com A를 두 번 — miss ~28ms → hit ~0ms, ID 재작성·TTL 감산·실
응답(압축 포인터·OPT 레코드 포함) 모두 정상.

**Windows도 이제 공용**: `dnscache`는 순수하게 `config`+`doh`만 의존하는 플랫폼
무관 모듈이라, Windows `udp_handler`(UDP/53)·`tcp_proxy`(TCP/53) 핸들러도
`doh.resolve` 대신 `dnscache.resolve`를 호출하도록 바꿨다. 반복 질의가 메모리 히트로
바뀌고 DoH 부하가 준다. `FREEGSM_DNS_CACHE=0`로 양쪽 모두 끌 수 있고, fail-closed·
stateless 불변식은 그대로다(캐시 이상 시 무캐시 `doh.resolve`로 폴백).

---

## 3. SNI/443 우회 — utun + tun2socks + SOCKS5

Network Extension은 Apple Developer 계정이 필요하므로, **utun 방식**으로 간다(root만
필요). 사실상 미니 VPN을 구현하는 셈이라 규모가 크지만 계정 의존성이 없다.

### 큰 그림

```
앱 --TCP--> [utun] --IP--> tun2socks(TCP종단) --SOCKS5--> 127.0.0.1:1080
                                                          (split_hello on :443,
                                                           upstream은 IP_BOUND_IF=en0)
```

성숙한 tun2socks가 utun 읽기·TCP 종단을 맡고, 각 흐름을 로컬 SOCKS5 프록시로
넘긴다. 프록시는 `:443`이면 `dpi.split_hello`로 ClientHello를 2레코드로 분할, 그
외는 패스스루. **TCP 스택 신규 구현 0줄** — 순수 Python으로 TCP 스택을 짜는 건
비현실적이라 성숙한 바이너리에 위임했다.

### 구성 요소

| 단계 | 내용 | 모듈 |
|------|------|------|
| 1. utun 생성·읽기 | `PF_SYSTEM`/`SYSPROTO_CONTROL` + `com.apple.net.utun_control` 제어 소켓으로 utun fd 확보, IP 패킷 read/write(앞 4바이트 AF 헤더) | `tunnel.py` (스파이크 U1로 검증) |
| 2. 라우팅 | 호스트 자기 트래픽을 utun으로. `route add 0/1`+`128/1`(기본 경로 덮어쓰기, VPN 트릭). **DoH 서버 IP·릴레이 upstream은 실 게이트웨이로 제외**(루프 방지) | `tunnel.py` |
| 3. TCP 종단 | utun으로 들어온 SYN을 종단해 바이트 스트림 확보 | **tun2socks 바이너리** |
| 4. 분할·중계 | 스트림에서 ClientHello → `dpi.split_hello` → 실서버 소켓으로 중계 | `socks_proxy.py` ([dpi.py](../dohproxy/dpi.py) 재사용) |
| 5. 비-443 패킷 통과 | 라우팅으로 utun에 들어온 나머지는 SOCKS 패스스루로 실서버 중계 | `socks_proxy.py` |
| 6. 원복 | 종료 시 라우트 삭제 + utun fd close(인터페이스 자동 소멸) | `tunnel.py` |

### ⚠️ 핵심 학습 — IP_BOUND_IF egress와 ifscope 경로

**루프 방지 핵심**: 프록시가 실서버로 나가는 upstream 소켓은 `IP_BOUND_IF` 소켓
옵션으로 물리 인터페이스(en0)에 고정 → default 경로가 utun이어도 우회한다.
(WinDivert 예약 포트 제외 절의 macOS 대응)

처음엔 SOCKS upstream이 전부 `ENETUNREACH`로 실패했다. 진단 결과:
`route get -ifscope en0 <ip>`가 **빈 결과** — 이 머신엔 en0의 ifscope(스코프) 경로가
없었다. `IP_BOUND_IF=en0`은 ifscope 라우팅 테이블을 보는데 거기 경로가 없으니
ENETUNREACH. **해결**: 터널 기동 시 **ifscope default 경로**를 하나 추가
(`route add -ifscope <iface> default <gw>`). 그러면 IP_BOUND_IF upstream 소켓은
ifscope→물리 인터페이스로 나가 utun을 우회하고, 앱 소켓(IP_BOUND_IF 없음)은 전역
`0/1` 경로로 utun에 들어가 분할이 유지된다. 전역 host-route 우회는 앱 트래픽까지
우회시켜 분할을 깨므로 부적합 — **소켓 단위 IP_BOUND_IF + ifscope가 정답**.

### 검증 (SNI/443)

```bash
curl https://example.com            # 앱 트래픽이 utun→tun2socks→SOCKS 경유
python verify_lolps.py [host]       # SNI 분할 동작 확인
```

> **라이브 검증됨 (2026-06-26)**: `curl https://example.com` / `www.cloudflare.com`
> → HTTP 200, SOCKS 로그에 `SNI=example.com ClientHello 321B -> 2 TLS records` 등
> 실제 트래픽 분할 확인. 종료 시 default route(en0)·시스템 DNS(DHCP) 완전 복원.

---

### 3.1 IPv6 우회

처음엔 IPv4만 redirect하고 IPv6 HTTPS는 SNI가 노출됐다(경고만 출력). 이제 호스트에
IPv6 default route가 있으면 v6도 터널에 태운다:

1. utun에 ULA v6 주소 부여 (`ifconfig utunX inet6 fd00:6f73:6d00::1 prefixlen 64`).
2. v6 ifscope default (`route add -inet6 -ifscope <if6> default <gw6>`) — SOCKS
   업스트림(`IPV6_BOUND_IF` 핀)이 utun 밖으로 나갈 경로. v4 ifscope와 동일 원리.
3. v6 DoH 제외 host-route — `DOH_URL`이 리터럴 v6일 때만(`DOH_SERVER_IP6`).
4. v6 default override (`route add -inet6 -net ::/1`/`8000::/1 -interface utunX`).

`netutil.split_relay`/SOCKS 업스트림 로직은 이미 family 무관이라 그대로 v6를 처리.
모든 v6 단계는 **best-effort** — 실패해도 동작 중인 v4 터널을 절대 깨지 않고 v6만
포기한다(그 경우 v6 SNI 노출, 경고). `FREEGSM_TUNNEL_IPV6=0`로 v6 redirect 비활성.

> v6 default가 **세션 중**에 생기면(예: 시작 후 VPN) 재시작 전까지 완전 redirect되지
> 않는다(utun v6 주소/디바이스 라우트는 start에서만 추가). netmonitor는 ifscope만 갱신.

---

## 4. 통합 main / 생명주기 / 원복

[`macos/main.py`](../dohproxy/macos/main.py): root 체크 → DoH upstream probe(fail-closed,
실패 시 기동 거부) → 리졸버 기동 → DNS 스왑 → (DPI on이면) SOCKS 서버 + utun 터널
기동 → `Ctrl+C`까지 대기 → teardown.

- **DPI는 graceful degrade**: tun2socks 바이너리가 없거나, `DOH_URL`이 리터럴 IP가
  아니거나(=터널에서 DoH 채널을 IP로 제외할 수 없음), 터널 셋업 중 예외가 나면 →
  DPI를 끄고 **DoH-only로 계속** 간다. DNS를 죽이느니 우회를 포기.
- **teardown 순서**: 라우팅 복원 → SOCKS 종료 → **DNS 복원(최우선)**. 각 단계가
  격리·idempotent이라 앞 단계 예외가 DNS 복원을 건너뛰지 못한다. `finally` +
  `signal`(SIGINT/SIGTERM/SIGHUP) + `atexit` 삼중으로 보장.
- **SIGHUP**: `run_macos.sh`를 띄운 터미널을 닫으면 정상 종료·복원.

---

### 4.1 네트워크 변경 견고성 (netmonitor)

Wi-Fi↔이더넷 전환·게이트웨이 변경·DHCP 갱신이 일어나면 `_gw`/`_iface`에 묶인
ifscope default·DoH 제외 host-route와 SOCKS의 `IP_BOUND_IF` 핀이 **stale**해져
업스트림이 `ENETUNREACH`로 죽는다. `macos/netmonitor.py`는 **이벤트 구동**이다:
커널 `PF_ROUTE`(`AF_ROUTE`) 라우팅 소켓을 읽어 라우트 add/change/delete 메시지가
오는 즉시(서브초) 반응하고, `MONITOR_INTERVAL`(기본 10s)은 라우트 메시지로 못 잡는
drift(서비스 DNS만 바뀌는 DHCP 갱신 등)를 위한 *바닥값*으로만 남긴다. 라우팅 소켓을
못 열면(드문 경우) 기존처럼 폴링으로 폴백. 라우트 버스트는 `_drain` + 짧은 settle로
한 번의 reconcile로 합친다. 변화 시:

- **터널 재적용** (`Tunnel.reapply_routes`): 디바이스 라우트(`.../1 → utun`)는
  그대로 두고 scoped 라우트만 삭제 후 새 gw/iface로 재생성 → 앱 트래픽은 끊김 없이
  계속 터널로 흐른다. `socks_proxy.set_bound_iface`로 업스트림 핀도 갱신. v6 default
  획득/상실도 여기서 `_enable/_disable_v6_device`로 반영.
- **DNS 재확인** (`dns_control.reconcile`): DPI 여부와 무관하게 항상 수행. 시작 후
  추가된 서비스(이더넷 연결·VPN)는 실 DNS를 **백업 후** `127.0.0.1`로, DHCP 갱신으로
  로컬 리졸버에서 벗어난 서비스는 백업을 **건드리지 않고** 다시 `127.0.0.1`로.

teardown은 **monitor를 가장 먼저 정지**(self-pipe로 `select()`를 깨움)해, 라우트/DNS
복원 중에 모니터가 그것을 다시 추가하는 레이스를 막는다. 데몬 스레드라 비정상 종료
시 함께 사라진다.

---

## 5. 배포 / 패키징

- **tun2socks 바이너리**: brew 포뮬러 없음 → GitHub 릴리스(v2.6.0) 바이너리를
  `./bin/tun2socks` 또는 PATH에 두거나 `FREEGSM_TUN2SOCKS`로 지정. `run_macos.sh`
  · `build_macos_app.sh`가 없으면 자동 다운로드.
- ✅ **더블클릭 앱**: [`packaging/build_macos_app.sh`](../packaging/build_macos_app.sh)
  → `dist/FreeGSM.app`. 더블클릭 토글(켜기/끄기). osascript 관리자 권한(=UAC)으로
  승격하되 실제 프로세스는 **launchd로 띄운다** — osascript 환경엔 tty가 없어 nohup
  분리가 실패(`can't detach from console`)하므로, baked LaunchDaemon plist를
  `/Library/LaunchDaemons`에 복사 후 `launchctl bootstrap`(시작)/`bootout`(중지,
  SIGTERM→정상 teardown). 검증 완료(start→`127.0.0.1#53`+200, stop→DHCP 복원).
- ✅ **터미널 종료 시 원복**: main.py가 SIGHUP 처리 → 띄운 터미널을 닫으면 정상 복원.
- ✅ **라이브 검증 하니스**: [`verify_macos.sh`](../verify_macos.sh) — 단위 테스트가
  닿지 못하는 실 utun/네트워크 경로(`status/doh/cache/sni/ipv6/netchange/killswitch/
  vpn`)를 상태 읽기 + `dig` 프로브로 확인(시스템 무변경). `netchange`·`vpn`은
  가이드형(사용자가 링크/VPN을 전환하면 스크립트가 ifscope 재적용·DNS 지속·누수
  차단을 확인). FreeGSM 기동 후 다른 터미널에서 실행.
- ⚠️ **.pkg 빌드 스크립트**: [`packaging/build_macos_pkg.sh`](../packaging/build_macos_pkg.sh)
  작성됨 — ad-hoc 서명(`codesign --sign -`) + `pkgbuild`까지. **Developer ID 서명·
  공증은 미적용** → 타인 배포 시 Gatekeeper 경고(우클릭 > 열기 필요). 공개 배포용
  서명·공증과 **메뉴바 UI**는 남은 과제.

---

## 6. 알려진 차이 / 한계 (Windows 대비)

- **DoH 보호 범위 차이**: Windows는 *모든* 아웃바운드 UDP/53·TCP/53을 목적지 불문
  캡처한다. macOS는 시스템 리졸버 스왑(시스템 리졸버 앱) + **DPI on 시 UDP ASSOCIATE로
  하드코딩 DNS 앱의 UDP/53도 DoH로 커버**([2.1절](#21-하드코딩-dns-커버--udp-associate)).
  **DPI off**: 업그레이드는 불가하나 opt-in `FREEGSM_BLOCK_PLAINTEXT_DNS=1`로 pf가
  비루프백 :53을 drop해 fail-closed(누수 차단). 기본 off([2.1절](#21-하드코딩-dns-커버--udp-associate)).
- **권한**: root 필요는 동일. pf/Network Extension과 달리 utun·DNS 조작은 코드서명
  없이 root면 가능 (Apple Developer Program 불필요).
- **QUIC/HTTP-3 (UDP/443)**: DPI on이면 `BLOCK_QUIC`(기본)로 **drop → TCP/443 폴백**
  (분할되는 경로로 유도). DPI off면 기본 미처리이나 opt-in
  `FREEGSM_BLOCK_PLAINTEXT_QUIC=1`로 pf가 UDP/443을 drop해 TCP 강제(SNI는 못 숨김,
  fail-closed)([2.1절](#21-하드코딩-dns-커버--udp-associate)).
- **IPv6**: v6 default가 있으면 redirect·분할([3.1절](#31-ipv6-우회)). 세션 중 v6
  획득/상실은 `netmonitor`가 `tunnel.reapply_routes` → `_enable/_disable_v6_device`
  로 재시작 없이 반영(라우트 소켓이라 거의 즉시).
- **네트워크 전환**: `netmonitor`가 `PF_ROUTE` 라우팅 소켓으로 라우트·핀·DNS를
  서브초 재적용([4.1절](#41-네트워크-변경-견고성-netmonitor)). `MONITOR_INTERVAL`은
  drift용 바닥값. (이전엔 폴링이라 최대 10s 지연.)
- **성능**: 443 릴레이가 userspace Python(SOCKS5) + tun2socks utun 홉을 거치는 점은
  동일. DNS는 `dnscache`로 반복 질의가 메모리 히트라 체감 개선([2.2절](#22-dns-캐시)).
- **VPN 공존**: 풀터널 VPN이 조용히 무력화하는 두 경우를 `netmonitor`가 **감지·경고**
  (자동 대응 X — VPN 라우트/리졸버와 싸우면 DNS 브릭 위험): (a) VPN이 configd로 DNS를
  설정해 유효 primary 리졸버가 `127.0.0.1`이 아니게 되면 `dns_control.verify_primary_resolver`
  (`scutil --dns`, `reconcile`에서 호출)가 DoH 우회 경고, (b) VPN이 같은 `0/1`+`128/1`
  트릭으로 디바이스 라우트를 뺏으면 `tunnel.device_routes_intact`(`netstat -rn`)가 SNI
  분할 우회 경고. `verify_macos.sh vpn`이 둘을 자동 확인 + VPN 토글 가이드.

---

# 부록 A — 폐기된 pf rdr 설계(기록)

> 아래는 1차 시도였던 **pf `rdr`** 방식이다. 스파이크 A에서 "로컬 발신 트래픽
> 가로채기 불가"가 확인되어 **폐기**됐고, 위 본문(utun + DNS 스왑)으로 대체됐다.
> 기록 목적으로만 보존한다.

## A.0 스파이크 A 결과 (2026-06-26) — pf rdr 불가

macOS 26.5.1, pf Disabled 상태에서 TEST-NET(198.51.100.1:9999) 대상 로컬 발신
연결이 로컬 리스너로 redirect 되는지 4가지 규칙으로 시험:

| 변형 | 결과 |
|------|------|
| A: `rdr pass on en0` | ❌ redirect 안 됨 |
| B: `rdr pass on lo0` | ❌ redirect 안 됨 |
| C: `rdr pass` (인터페이스 미지정) | ❌ redirect 안 됨 |
| D: `pass out route-to (lo0 127.0.0.1)` | ❌ (애초에 포트 변환 불가, 무효 테스트) |

**결론**: macOS pf의 `rdr`은 인터페이스로 **들어오는(inbound)** 패킷에만 적용되며,
이 호스트가 스스로 만들어내는 아웃바운드 연결에는 매칭되지 않는다. Linux `iptables
OUTPUT REDIRECT` 대응 메커니즘이 macOS pf엔 없고 `divert-to`도 없다(OpenBSD pf
포크라 `divert-to`/`divert-packet` 제거됨). 따라서 **pf 단독으로는 로컬 발신
트래픽의 투명 가로채기 불가** → pf 방식 폐기.

## A.1 원래 pf 설계 개요 (참고)

pf가 동작했다면 의도했던 모델:

| | Windows (WinDivert) | macOS (pf, 폐기) |
|---|---|---|
| 가로채기 | 전 패킷 캡처 후 주소 재작성·재주입 | 커널이 `rdr`로 목적지 재작성 (자동) |
| 복귀 경로 | `_conn_map`으로 응답 src 수동 복원 | pf NAT 상태가 자동 역변환 |
| 원본 목적지 | 패킷에 그대로 있음 | `/dev/pf` `DIOCNATLOOK` ioctl로 조회 |
| 권한 | Administrator (드라이버 로드) | root (`pfctl` + `/dev/pf`) |
| 종료 시 원복 | 핸들 닫으면 끝 | 앵커 flush + pf 원상복구 |

후보였던 rdr 규칙과 원본 목적지 복구(`DIOCNATLOOK`), 전용 앵커(`com.freegsm`)
생명주기 설계 등은 스파이크 A 실패로 구현되지 않았다. 핵심 통찰("로컬 발신 redirect
가부가 전체 설계의 전제")은 검증으로 부정됐고, 그 자리를 utun이 대체했다.
