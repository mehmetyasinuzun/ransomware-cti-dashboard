# Ransomware Monitoring Dashboard

Ransomware saldırılarına ilişkin verileri açık tehdit istihbaratı kaynaklarından çekip işleyen, analiz eden ve görselleştiren bir **Cyber Threat Intelligence (CTI)** panosu.

Sistem; saldırı grupları, hedef ülkeler, sektörler ve zaman bazlı trendler üzerinden analiz sunar, her kayıt için savunulabilir bir **severity (1–10)** puanı türetir ve IP / dosya hash'i ile sorgulanabilen bir **IOC arama modülü** içerir.

> Veri tek bir hazır dosyadan değil, üç ayrı canlı API'den (ransomware.live, abuse.ch, MITRE ATT&CK) çekilip birleştirilerek üretilir. Hazır Kaggle veri seti **kullanılmamıştır.**

---

## Mimari

Üç servis, tek bir veri hacmi (`./data`) üzerinden konuşur:

```
  ransomware.live ─┐
  abuse.ch         ├─►  pipeline (Go)  ──►  data/cti.db  ◄── server (Go API)
  MITRE ATT&CK    ─┘     tek seferlik         SQLite           │  REST /api/*
                                              dataset.csv      ▼
                                              dataset.json   frontend (React + nginx)
                                                               http://localhost:8080
```

| Bileşen | Teknoloji | Görev |
|---|---|---|
| **pipeline** | Go (tek statik binary) | API'lerden veri çeker, zenginleştirir, severity hesaplar, SQLite + CSV/JSON üretir |
| **server** | Go (net/http, modernc SQLite — CGO'suz) | Analitik sorgular ve IOC arama için REST API |
| **frontend** | React + TypeScript + Vite + Apache ECharts | Koyu temalı, etkileşimli pano (nginx ile servis edilir) |
| **veritabanı** | SQLite (WAL) | Gömülü, ayrı servis gerektirmez |

Go tercih edildi: tek statik binary, küçük (~20 MB) ve bağımlılık kaymasına kapalı imaj, goroutine ile kontrollü-paralel veri çekimi. Analiz SQL ile, MITRE zenginleştirmesi düz JSON eşlemesiyle yapıldığından pandas benzeri bir bağımlılığa ihtiyaç yoktur.

---

## Veri Kaynakları

Tüm kaynaklar açık ve ücretsizdir. Pipeline bunları çekip **brief'in istediği şemaya** dönüştürür.

### 1. ransomware.live API v2 — `https://api.ransomware.live/v2`
Ransomware gruplarının veri sızdırma sitelerinden (DLS) ve OSINT kaynaklarından derlenen **gerçek kurban kayıtları.** Kimlik doğrulama gerektirmez.
- `GET /victims/{yıl}/{ay}` — aylık kurban kayıtları (kurum, grup, ülke, sektör, tarih)
- `GET /group/{ad}` — grup profili; **MITRE ATT&CK TTP'lerini** (`ttps`: taktik + teknik kodu/adı) içerir

### 2. abuse.ch — ThreatFox (+ MalwareBazaar)
Ransomware aileleri için **gerçek IOC'lar.** İki çalışma modu vardır:
- **Varsayılan (anahtarsız):** ThreatFox'un herkese açık **tam export** dosyası (`/export/json/full/`) indirilir; ransomware ailelerine ait gerçek IP ve hash göstergeleri ayıklanıp gruplara eşlenir. Auth-Key **gerekmez**, gerçek veridir.
- **Auth-Key ile (opsiyonel, en güncel):** `ABUSECH_AUTH_KEY` verilirse ThreatFox `malwareinfo` + MalwareBazaar `get_siginfo` canlı API'leri kullanılır.
- Grup adı → aile eşlemesi (`lockbit→win.lockbit`, `alphv→win.blackcat`, vb.) statik tablo ve sezgisel adlandırmayla yapılır.

> Yalnızca export indirilemezse (tam çevrimdışı) pipeline son çare olarak deterministik **sentetik** IOC üretir; bu kayıtlar `synthetic` kaynak etiketiyle açıkça işaretlenir. Teslim edilen anlık görüntü gerçek ThreatFox verisiyle üretilmiştir.

### 3. MITRE ATT&CK
Teknik kodları ve adları doğrudan ransomware.live grup profillerinden (kendileri MITRE ile eşlenmiştir) gelir. `attack_vector`, Initial Access (TA0001) teknikleri üzerinden türetilir.

---

## Veri Şeması

Her kayıt brief'in istediği alanları içerir. Üretilmiş veri seti `data/dataset.csv` ve `data/dataset.json` dosyalarındadır.

| Alan | Kaynak / Türetim |
|---|---|
| `date` | ransomware.live `attackdate` (esnek tarih ayrıştırma) |
| `ransomware_group` | ransomware.live `group` |
| `country` | ransomware.live `country` (ISO-2) |
| `target_sector` | ransomware.live `activity` |
| `attack_vector` | Grubun MITRE Initial Access tekniklerinden; profili olmayan gruplarda CISA'nın belgelediği baskın vektörlere düşülür |
| `technique` | Grubun MITRE ATT&CK TTP kümesinden temsilî teknik (T-kodu + ad) |
| `severity` | Aşağıdaki ağırlıklı model ile hesaplanır (1–10) |
| `ioc_ip` (ops.) | abuse.ch ThreatFox (gerçek) veya sentetik |
| `ioc_hash` (ops.) | abuse.ch MalwareBazaar (gerçek) veya sentetik |

---

## Severity Metodolojisi

Severity kaynak veride **yoktur**; CVSS v4'ün katmanlı (içsel etki + tehdit bağlamı + çevresel) mantığını model alan, şeffaf ve ağırlıklı bir bileşik puan olarak türetilir. Bileşenlerin her biri 0–10'a normalize edilir, ağırlıklarla toplanır ve 1–10 aralığına sıkıştırılır:

```
severity = clamp(1, 10,
    0.30 · sektör_kritikliği     # CISA 16 kritik altyapı sektörü
  + 0.25 · grup_aktivitesi       # grubun kurban sayısının log-ölçekli payı
  + 0.15 · etki_tekniği          # grupta MITRE Impact tekniği (T1486 vb.) var mı
  + 0.15 · tazelik               # saldırı tarihinin güncelliği (üstel azalma)
  + 0.15 · ioc_varlığı           # grupla eşleşen aktif IOC var mı
)
```

Model `internal/enrich/severity.go` içinde, ağırlıklar dosyanın başında tek yerde tanımlıdır. Amaç sahte kesinlik değil, izlenebilir ve savunulabilir bir önceliklendirmedir.

---

## İstenen Özellikler — Karşılanma

**Veri analizi:** grup / ülke / sektör dağılımları, zaman bazlı trendler ve ortalama severity, SQL agregasyonlarıyla API üzerinden sunulur.

**Dashboard (4+ görselleştirme):**
- Genel Bakış — KPI özet ekranı + 4 grafik
- Tehdit Grupları — grup dağılım grafiği + saldırı vektörleri + MITRE teknikleri + tam tablo
- Coğrafya & Sektör — dünya choropleth haritası + ülke ve sektör dağılımları
- Zaman Serisi — aylık saldırı hacmi ve ortalama severity (çift eksen)

**IOC Arama Modülü:** Girilen IP veya hash için ilgili ransomware grubunu, eşleşen göstergeleri, ilgili saldırı kayıtlarını ve severity özetini listeler.

---

## Veri Tazeleme ve Güncellik

Veri, çekildiği andaki bir **anlık görüntüdür** (üst barda "çekilme zamanı" gösterilir). Güncel tutmak için üç mekanizma vardır:

- **"Yenile" butonu (arayüz):** Üst bardaki buton `POST /api/refresh` ile veriyi kaynaklardan arka planda yeniden çeker; bittiğinde pano otomatik tazelenir. Terminale dönmeye gerek yoktur.
- **Otomatik tazeleme:** Sunucu `REFRESH_INTERVAL_HOURS` (Docker'da varsayılan **24 saat**) aralığıyla veriyi kendiliğinden günceller. `0` yapılırsa kapanır.
- **Zaman aralığı seçici:** Üst bardan **Tümü / 1 Yıl / 6 Ay / 30 Gün** seçilerek tüm analiz o pencereye daraltılır. "son 30 gün" gibi metrikler en güncel kayda göre hesaplanır; otomatik tazeleme açıkken bu değerler gerçek zamanı takip eder.

İlk kez `docker compose up` çalıştırıldığında veritabanı boşsa sunucu ilk çekimi kendi tetikler; hazır anlık görüntü mevcutsa onu kullanır.

## Çalıştırma

### Seçenek A — Docker (önerilen)

Gereksinim: Docker + Docker Compose.

```bash
docker compose up --build
```

Pano: **http://localhost:8080**

`./data/cti.db` zaten mevcut olduğundan (hazır anlık görüntü repo ile gelir) pipeline çekimi atlar ve uygulama **çevrimdışı** açılır. Veriyi API'lerden yeniden çekmek için (varsayılan olarak ThreatFox export'undan gerçek IOC dahil):

```bash
REFRESH=true docker compose up --build
```

İsteğe bağlı olarak en güncel IOC için `.env.example`'i `.env`'e kopyalayıp `ABUSECH_AUTH_KEY` girebilirsiniz; ama anahtarsız da gerçek veri çekilir.

### Seçenek B — Manuel (geliştirme)

Gereksinim: Go 1.25+, Node 20+.

```bash
# 1) Veri çek (ilk sefer; sonraki açılışlarda atlanır)
cd backend
DATA_DIR=../data go run ./cmd/pipeline

# 2) API sunucusu (yeni terminal)
DB_PATH=../data/cti.db go run ./cmd/server      # :8080

# 3) Arayüz (yeni terminal)
cd ../frontend
npm install
npm run dev                                      # :5173 (/api -> :8080 proxy)
```

> Windows PowerShell'de ortam değişkenleri: `$env:DB_PATH='../data/cti.db'; go run ./cmd/server`

### Yapılandırma

Tüm ayarlar ortam değişkeniyle yapılır (bkz. `.env.example`): `ABUSECH_AUTH_KEY`, `WINDOW_FROM`, `REFRESH`, `THROTTLE_MS`.

---

## Proje Yapısı

```
.
├── backend/                  Go modülü (pipeline + server, paylaşılan internal/)
│   ├── cmd/pipeline/         Veri çekme + zenginleştirme + dışa aktarma
│   ├── cmd/server/           REST API
│   └── internal/
│       ├── sources/          ransomware.live ve abuse.ch istemcileri
│       ├── enrich/           severity, sektör, ülke, MITRE, IOC mantığı
│       ├── store/            SQLite şema, yazma ve sorgular
│       ├── httpx/            throttle + 429 backoff'lu HTTP istemcisi
│       └── ...
├── frontend/                 React + TS + Vite + ECharts
│   └── src/{views,components,lib}
├── data/                     Üretilen veri seti (cti.db, dataset.csv, dataset.json)
├── docker-compose.yml
└── README.md
```

---

## API Uç Noktaları

| Uç nokta | Açıklama |
|---|---|
| `GET /api/summary` | KPI özetleri + meta |
| `GET /api/groups` · `/countries` · `/sectors` | Dağılımlar |
| `GET /api/attack-vectors` · `/techniques` | MITRE dağılımları |
| `GET /api/timeseries` · `/severity` | Zaman serisi ve severity dağılımı |
| `GET /api/victims` | Filtrelenebilir, sayfalı kayıtlar |
| `GET /api/ioc?q=<ip\|hash>` | IOC sorgulama (atıf) |
| `GET /api/iocs` · `/api/ioc-groups` | IOC kataloğu (filtreli, sayfalı) |
| `POST /api/refresh` · `GET /api/refresh/status` | Veriyi yeniden çek / durumu sorgula |

Analitik uç noktaları (`summary`, `groups`, `countries`, `sectors`, `timeseries`, `severity`, `attack-vectors`, `techniques`) opsiyonel `window=30d\|180d\|365d` parametresini kabul eder.

---

## Lisans

Kaynak kod [MIT](LICENSE) lisansı altındadır. Veri kaynakları kendi kullanım şartlarına tabidir: ransomware.live ("personal use only"), abuse.ch (ThreatFox / MalwareBazaar) ve MITRE ATT&CK.

---

Yıldız · Cyber Threat Intelligence