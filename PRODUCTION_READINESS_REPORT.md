# WireRift Production Readiness Raporu

Tarih: 3 Kasım 2026  
Kapsam: Go sunucu, istemci, protokol/multiplexer, HTTP/TCP edge, kimlik doğrulama, dashboard, TLS/ACME, CLI/config, testler, Docker, CI ve release zinciri.  
Kapsam dışı: `website/` — kullanıcı talebiyle ayrı repoya taşınmış eski içerik olarak değerlendirilmedi.

## Yönetici özeti

WireRift'in çekirdek mimarisi güçlü: stdlib-only tek binary yaklaşımı, özel multiplexing protokolü, HTTP/TCP/WebSocket tünelleri, hesap kapsamlı yetkilendirme, rate limit, canlı token reload, ACME, trafik inceleme, reconnect/offline grace ve geniş test matrisi gerçekten uygulanmış durumda.

Bu audit öncesinde ve production hazırlığı sırasında sistemin production iddiasını zedeleyen 21 doğrulanmış sorun vardı: bir kritik, 16 yüksek ve dört orta önem düzeyi. Tamamı dar kapsamlı düzeltmeler ve regresyon testleriyle kapatıldı. En kritik değişiklik, ACME açıkken control plane'in yine plaintext kalmasıydı; bu durumda auth token ağda açık metin taşınıyordu. ACME artık HTTPS edge ile birlikte control plane'i de TLS'e alıyor ve başlatılamazsa production CLI sessizce self-signed moda düşmüyor.

Kod ve tek-node container seviyesi için sonuç: **koşullu production-ready**. Readiness/metrics ve image supply-chain kapıları tamamlandı. Public trafiğe açılmadan önce gerçek DNS/ACME staging provası, secret/network politikası, yedekleme/geri yükleme tatbikatı ve operasyon runbook'u gerçek ortamda tamamlanmalı.

## Mevcut mimari ve güçlü taraflar

- Go stdlib dışında runtime/modül bağımlılığı yok; `go.sum` boş kalıyor ve CI artık bunu doğruluyor.
- Control plane, mux ve stream lifecycle için kapsamlı unit/integration/race testleri var.
- HTTP edge; streaming, WebSocket, half-close, idle timeout, body budget, request ID, PIN, Basic Auth ve IP whitelist davranışlarını kapsıyor.
- Auth tarafı token hash'i, hesap kapsamı, canlı dosya reload'u, session revoke ve hesap limitlerini doğru uyguluyor.
- Custom-domain sahipliği HMAC tabanlı DNS TXT kanıtıyla doğrulanıyor.
- Sertifika cache'i, ACME order eşzamanlılığı, yenileme ve local CA name constraints kapsamlı test edilmiş.
- Dashboard varsayılan olarak loopback'te; API verileri hesap kapsamına göre filtreleniyor.
- CI; Linux/macOS/Windows, race, fuzz, advanced suite, %90 coverage ve Docker build kapılarına sahip.
- Container non-root çalışıyor; persistent certificate volume ve healthcheck var.
- `/healthz` liveness, lifecycle-aware `/health/ready` readiness ve Prometheus uyumlu `/metrics` mevcut; Docker healthcheck readiness kullanıyor.

## Doğrulanıp düzeltilen bulgular

| ID | Seviye | Alan | Sorun ve yapılan düzeltme |
|---|---|---|---|
| F1 | Yüksek | Server lifecycle | HTTP bind hatası control listener'ı açık bırakıyordu. Startup rollback ve goroutine wait eklendi. |
| F2 | Yüksek | Config/input | Bozuk, ters veya 0/65535 dışı TCP port aralıkları kabul ediliyordu. Listener açılmadan strict parse/validation eklendi. |
| F3 | Yüksek | Wire protocol | Frame/magic yazımı kısa `Write` sonucunu başarı sayıp eksik veri üretiyordu. Progress kontrollü full-write uygulandı. |
| F4 | Orta | PIN guard | Yeni IP'lerle PIN failure map'i 10.000 sınırını aşabiliyordu. Stale eviction ve kapasitede fail-closed davranış eklendi. |
| F5 | Yüksek | Client race | Eski heartbeat goroutine'i yeni bağlantıyı `disconnected` işaretleyebiliyordu. Bağlantı generation/ownership kontrolü eklendi. |
| F6 | Yüksek | TCP relay | Mux reset sonrası sessiz local peer relay goroutine/socket'ini sonsuza kadar tutabiliyordu. Hata yolunda full close, normal EOF'ta half-close korundu. |
| F7 | Yüksek | TLS concurrency | İptal edilmiş TLS handshake, paylaşılan sertifika issuance'ını iki dakikaya kadar bekliyordu. Waiter kendi context iptaline cevap veriyor. |
| F8 | Yüksek | Sertifika bütünlüğü | `writeFileAtomic` hedef dosyayı başarıdan önce truncate ediyordu. Temp + sync + close + rename ile son sağlam sertifika korunuyor. |
| F9 | Yüksek | ACME input | Sekiz karakterden kısa challenge token log dilimlemesinde panic oluşturuyordu. Güvenli kısaltma eklendi. |
| F10 | Yüksek | ACME input | Hatalı ACME URL parse hatası yok sayılıp nil request dereference ediliyordu. Request oluşturma hatası artık döndürülüyor. |
| F11 | Yüksek | CLI startup | Dashboard bind hatası yalnızca loglanıyor, diğer servisler kısmi çalışıyordu. Dashboard listener diğer servislerden önce reserve ediliyor. |
| F12 | Yüksek | Config güvenliği | YAML/JSON'de `auth`, `pin` gibi yanlış yazılmış alanlar sessizce yok sayılıyordu. Unknown/malformed alanlar artık fail-closed. |
| F13 | Orta | Quality gate | Local coverage script %70 ve CI'dan farklı package seti kullanıyordu. CI ile aynı paketler ve %90 eşik uygulandı; `bc` bağımlılığı kaldırıldı. |
| F14 | Yüksek | Supply chain | Release Go 1.23 ve runtime Alpine 3.20 artık destek dışıydı. Go 1.27, Alpine 3.24 ve golangci-lint v2.15'e geçildi. |
| F15 | Kritik | Control security | ACME açıkken control plane plaintext kalıyor, token açık metin taşınıyordu. ACME sertifikası control plane'de de kullanılıyor; plaintext bağlantı reddediliyor. |
| F16 | Yüksek | HTTPS startup | TLS yapılandırılmışken 443 bind hatası yalnızca warning üretip plaintext/kısmi servis başlatıyordu. HTTP/control rollback ve fatal startup error eklendi. |
| F17 | Yüksek | ACME identity/lifecycle | Bozuk account key sessizce yeni kimlikle değiştiriliyordu; outage restart'ı geçerli cache'i de kullanamıyordu. Existing key artık fail-closed ve atomik; yalnız sağlam identity + geçerli base sertifikasıyla degraded startup yapılıyor, ACME beş dakikada bir geri bağlanıyor. |
| F18 | Yüksek | Proxy trust | Doğrudan ziyaretçinin gönderdiği sahte `X-Forwarded-For` zincire eklenip backend'e taşınıyordu. Edge artık bu untrusted değeri atıyor ve backend'e yalnız socket peer IP'sini tekil olarak yazıyor. |
| F19 | Yüksek | Trusted proxy boundary | L7 proxy arkasında bütün ziyaretçiler proxy IP'sine çöküyor ve güvenli original-IP kurtarma ayarı bulunmuyordu. Açık CIDR allowlist, sağdan-sola chain çözümleme, 32-hop sınırı ve malformed-chain fail-closed davranışı eklendi; rate limit, allowlist, PIN, inspection, stream metadata ve backend aynı kimliği kullanıyor. |
| F20 | Orta | Dashboard auth performansı | Guard kapasitede her yeni IP için 10.001 kayıt üzerinde O(n) en-eski taraması yapıyordu; ölçüm 166.004 ns/op ve mevcut-IP güncellemesine göre 2.101x yavaşlama gösterdi. Exact-cap O(1) LRU sonrası kalıcı benchmark 242–248 ns/op ölçüyor. |
| F21 | Orta | Operasyon gözlemi | Request/error rate, latency histogramı, certificate expiry ve persistence write failure sinyalleri yoktu. Sabit status-class etiketleri, global sabit bucket'lar, yan etkisiz in-memory expiry callback'i ve server+TLS write-error counter'ı eklendi; health/metrics/ACME trafiği kendi sayacını şişirmiyor. |

Her yüksek/kritik concurrency, ownership, input veya lifecycle bulgusu kalıcı regresyon testiyle koruma altında. Audit kanıtları ve üçlü doğrulamalar `.temp_files/` altında tutuluyor; klasör git tarafından ignore ediliyor.

## Build, deployment ve release düzeltmeleri

- CI ve release toolchain'i Go 1.27.x'e taşındı. Go'nun resmi politikasına göre bir major sürüm iki yeni major çıktıktan sonra destekten düşüyor; güncel stable 1.27 serisi kullanılıyor: <https://go.dev/doc/devel/release>.
- Runtime image `alpine:3.20` yerine `alpine:3.24` oldu. Alpine'ın resmi tablosunda 3.20 normal desteği 1 Nisan 2026'da bitmiş durumda: <https://alpinelinux.org/releases/>.
- golangci-lint v1 config'i v2 formatına geçirildi; CI action v9 ve linter v2.15 kullanıyor.
- Release tag event'inde boş kalabilen `head_commit.timestamp` yerine commit tarihi doğrudan Git'ten alınıyor.
- Makefile build/release çıktıları version, kısa commit ve build date metadata'sını birlikte içeriyor; release loop ilk build hatasında duruyor.
- Compose artık domain, güçlü token ve ACME e-postası verilmeden başlamıyor. Public domain için self-signed default kaldırıldı.
- Compose içindeki örnek nginx servisi `example` profile'ına alındı; production default ile gereksiz servis başlamıyor.
- Docker image Go 1.27/Alpine 3.24 ile build edildi; non-root kullanıcıyla başlatıldı, healthcheck `healthy` oldu ve iki binary doğru version/commit/date bildirdi.
- Builder/runtime base image'ları multi-platform manifest digest'lerine, CI ve release action'ları tam commit SHA'larına sabitlendi; Dependabot haftalık action ve Docker digest güncellemesi açıyor.
- CI imajı HIGH/CRITICAL OS ve Go binary CVE'lerinde fail ediyor ve SPDX 2.3 SBOM yayınlıyor. Release binary'leri GitHub/Sigstore provenance attestation alıyor; container'a SBOM, max-level provenance ve imzalı registry attestation ekleniyor.

## Doğrulama sonuçları

- Unit + integration: `./cmd/... ./internal/... ./test/integration/` — geçti.
- Race detector: aynı tam paket seti — geçti.
- Advanced security/stress/reconnect/soak suite — 34/34 geçti.
- Fuzz: altı CI hedefi toplam 135 saniye fuzz süresiyle geçti.
- Coverage: toplam **%91,2**, zorunlu eşik **%90** — geçti.
- `go vet` — geçti.
- golangci-lint v2.15 — `0 issues`.
- Zero-dependency kontrolü — geçti.
- Docker build, Compose config, non-root startup, readiness healthcheck ve embedded metadata — geçti.
- Trivy 0.76.1 HIGH/CRITICAL CVE kapısı — **0 bulgu**; SPDX 2.3 SBOM üretim/parse kontrolü — geçti.
- actionlint 1.7.12 ile CI/release workflow semantik ve expression kontrolü — geçti; production workflow'larında mutable action ref kalmadı.
- `git diff --check` — geçti.

Gerçek Let's Encrypt veya public DNS'e audit sırasında istek gönderilmedi. ACME davranışı kontrollü fake server/transport ile test edildi; gerçek staging provası deployment kapısıdır.

## Eksikler ve kalan riskler

### P0 — public production açılışından önce

1. **Gerçek staging provası:** Ayrı staging domain ile A/AAAA ve wildcard DNS, public 80/443/4443, ACME HTTP-01, `tls://` control bağlantısı, HTTP/WebSocket/TCP tünelleri ve certificate renewal gözlenmeli.
2. **Secret yönetimi:** CLI artık `WIRERIFT_TOKEN_FILE` destekliyor ve Compose bootstrap token'ı read-only secret olarak mount ediyor. Gerçek platform secret store, erişim/rotasyon sahipliği ve persistent volume şifrelemesi deployment'ta uygulanmalı.
3. **Backup/restore tatbikatı:** Certificate volume şifreli yedeklenmeli. Özellikle `domain-secret` kaybı yayınlanmış bütün custom-domain TXT kanıtlarını; ACME account key kaybı hesap sürekliliğini etkiler. Restore testi yapılmadan backup var sayılmamalı.
4. **Network politikası:** Yalnız 80/443/4443 ve seçilen TCP range public; dashboard yalnız `127.0.0.1:4040` veya TLS reverse proxy arkasında olmalı. Container/orchestrator security group kuralları bununla eşleşmeli.
5. **Operasyon runbook'u:** `docs/OPERATIONS.md` deploy, canary, rollback, token revoke, ACME/cert, port, disk ve backup/restore prosedürlerini tanımlıyor. Public açılıştan önce tabloda gerçek primary/backup sahipleri atanmalı ve restore/staging adımları fiilen yürütülmeli.

### P1 — bu audit turunda tamamlandı

Trusted-proxy CIDR modeli, dashboard guard saturation performansı ve sabit-cardinality request/error/latency/certificate/persistence metrikleri kalıcı test ve ölçümlerle tamamlandı. İlk production iterasyonunda bu sinyaller için gerçek SLO ve alarm eşikleri canary verisinden kalibre edilmeli.

### P2 — ölçek ve yüksek erişilebilirlik

1. Çok-node edge için paylaşılan session/tunnel ownership, distributed rate limits ve certificate coordination yok; mevcut ürün bilinçli olarak single-node.
2. Multi-instance/rolling deploy, uzun süreli soak, packet loss/latency injection ve yüksek eşzamanlı stream kapasite testleri eklenmeli.
3. SLO'lar tanımlanmalı: control connect başarı oranı, tunnel setup p95, edge latency overhead, reconnect süresi, ACME renewal başarı oranı ve error-budget.
4. Büyük `server.go`, `client.go` ve dashboard dosyaları davranış değiştirmeden lifecycle/transport/registry katmanlarına ayrılmalı; bu P0 değil, bakım maliyeti işidir.

## Önerilen yayın sırası

1. Bu değişiklikleri PR'a al; CI'nın yeni Go/linter/Docker matrisiyle yeşil olduğunu doğrula.
2. `vNext-rc1` üret; checksum, binary metadata, Docker digest ve SBOM'u kaydet.
3. Ayrı staging sunucuda P0 gerçek ACME/DNS provası ve 24–72 saat soak çalıştır.
4. Backup al, sıfır makineye restore et ve aynı custom-domain kanıtlarının çalıştığını doğrula.
5. Dashboard'u loopback/reverse proxy arkasına, token'ı secret store'a, firewall'ı allowlist'e bağla.
6. Canary production node aç; `/health/ready` ve `/metrics` sinyallerini alarm sistemine bağla.
7. Canary stabilse stable tag ve immutable image digest ile yayınla; rollback digest'ini hazır tut.

## Son karar

Çekirdek kodda audit sırasında kanıtlanmış açık hata bırakılmadı; temel readiness/metrics ve supply-chain katmanları eklendi, test kapıları production seviyesine yükseltildi. WireRift bugün **tek-node, kontrollü deployment için release candidate** durumunda. “Genel erişime tamamen production-ready” etiketi, kodla kanıtlanamayacak P0 gerçek staging/backup/network/runbook kapıları uygulamada tamamlandıktan sonra verilmelidir.
