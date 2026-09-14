# Elyra — AI proje sözleşmesi ve devam dosyası

<!-- AI_CONTEXT:v2 | updated: 2026-09-12 | single-handoff-source | local-first -->

Bu dosya, projeye katılan herhangi bir AI agent'ın önce okuyacağı tek ve otoriter bağlamdır. Kod yazmadan önce bunu, `README.md`'yi ve ilgili teknik belgeleri oku. Her çalışma sonunda güncellenir.

## Proje kimliği

- Ürün adı: **Elyra** (eski kod/servis adları ELYRA/Elyra geriye dönük uyumluluk için korunur).
- Depo: `https://github.com/mustafaoyan/Elyra`
- Amaç: entropy, dosya yapısı, MIME, izin ve platform telemetrisiyle açıklanabilir, cihaz-içi savunma.
- Linux geliştirmesi aktif; Windows W1'de duraklatıldı. Bulut yönetimi, uzaktan günlükleme ve dosya yükleme yok.
- Entropy/heuristik skor tek başına malware kanıtı değildir; ölçülmemiş tespit yüzdesi yayınlanmaz.

## Değişmez güvenlik sözleşmesi

```json
{"cloud_management":false,"remote_logging":false,"malware_execution":false,"windows_enforcement":"MONITOR_ONLY","entropy_is_proof":false,"automatic_delete_default":false,"inconclusive_is_clean":false}
```

Eksik, okunamayan, değişen veya desteklenmeyen dosya `INCONCLUSIVE` olur ve GUI'de `N/A` görünür. Kayıp sensör/kuyruk taşması “korunuyor” sayılmaz. Destructive response yalnız açık yerel politika ve yetkiyle, tercihen geri alınabilir karantina olarak uygulanır.

## Mimari ağaç

```text
elyra-engine/src/elyra/
├─ analyzer/{entropy.py,static_analyzer.py,pe.py,pre_execution.py}
├─ scoring/engine.py             # Deterministik açıklanabilir skor
├─ monitor/{fanotify,ebpf,windows}
├─ correlation/engine.py         # Linux olay korelasyonu
├─ response/                     # Karantina/geri alma
├─ audit/                        # Yerel tamper-evident JSONL
├─ service/{daemon.py,windows_local.py}
└─ gui/                          # CustomTkinter + Matplotlib
elyra-engine/{scripts,tests,packaging,docs}
landing/{index.html,assets/css,assets/js,update-manifest.json}
```

`entropy.py` tek Shannon entropy kaynağıdır. Ortak scanner/scoring kopyalanmaz; platform farkı adapter sınırında kalır. PE parser yalnız sınırlı header/section kanıtı çıkarır; kod çalıştırmaz, arşiv açmaz, import/disassembly veya Authenticode trust doğrulamaz.

## Kodlama ve isimlendirme standardı

- Python >=3.10, UTF-8, 4 boşluk, PEP8; fonksiyon/modül `snake_case`, sınıf `PascalCase`, sabit `UPPER_SNAKE_CASE`.
- Public API'lerde tip ipucu ve kısa docstring; dönüşler dataclass/açık JSON sözleşmesi.
- Her parser/IO işleminde byte, süre, bellek ve derinlik bütçesi; sınırsız okuma, shell çalıştırma ve ağ çağrısı yok.
- Hataları yutma: `INCONCLUSIVE`, `DEGRADED_*`, `UNAVAILABLE_*` durumlarını açık taşı.
- UI yalnız gerçek sensör verisini gösterir; animasyon telemetri uydurmaz. Hassas dosya içeriği uzak servise gönderilmez.
- Yeni davranış: birim/regresyon testi → platform kanıtı → dokümantasyon. Zararlı indirme/çalıştırma yerine sentetik benign fixture.

## Platform durumu

### Linux (aktif)

L0 baseline, L1 kernel-header resolver, L2 fanotify capability, L3 eBPF/tracefs capability, L4 pre-execution kimliği, L5 audit sağlık durumu, L6 resilience benchmark ve L7 release gate tamamlandı. Native kanıt gerçek, uyumlu Linux hostunda root ile alınabilir; Windows makinesindeki test bunun yerine geçmez.

```bash
cd elyra-engine
PYTHONPATH=src python scripts/linux_baseline.py
PYTHONPATH=src python scripts/test_linux_capacity.py
sudo PYTHONPATH=src python scripts/test_linux_capacity.py --live --output evidence/capacity/linux_capacity.json
PYTHONPATH=src python scripts/release_gate.py
```

Header resolver dry-run'dır; `--apply` root ister ve kernel build dizinini ezmez. Fanotify/eBPF önce `READY`, `DEGRADED` veya `UNAVAILABLE` raporlar.

### Windows (duraklatılmış W1)

Ortak statik scanner/scorer, sınırlı PE kanıtı, `ReadDirectoryChangesW` fallback, ETW adapter sınırı, kuyruk/yeniden deneme/yerel yol limitleri ve monitor-only GUI hazırdır. İmzalı minifilter, execution blocking, Authenticode trust, YARA, ML/LLM ve sandbox yapılmadı. Windows'a ancak kullanıcı yeni aşama başlatırsa dönülür.

## Tamamlanan çalışmalar

1. Local-first mimari, bulut/uzak günlükleme sınırı.
2. Windows W1 statik analiz ve monitor-only bildirim hattı.
3. Linux L0–L7 araçları ve kabul kapıları.
4. Türkçe, Linux-only landing page ve renkli E favicon.
5. Yerel update manifesti; zorunlu güncelleme `can_defer:false`.
6. Linux `.deb` Release v1.0.2 + SHA256 sidecar doğrulaması.
7. GitHub deposu `mustafaoyan/Elyra` olarak yeniden adlandırıldı ve bağlantılar güncellendi.
8. Elyra isimlendirme refaktörü sonrası Windows doğrulaması tamamlandı: `255 passed`, `11 skipped`, `0 failed`; entropy-only fixture OS temp bağlamından izole edildi.

## Gelecek planı (başlatma izni olmadan uygulama yok)

İlk hedef **M2 — yerel imza kuralları ve zengin statik kanıt**:

- [ ] Provenance/sürüm/içerik hash'li yerel hash-signature şeması.
- [ ] YARA-X değerlendirmesi ve benign/pozitif/bozuk kural testleri.
- [ ] Bounded PE import/export, section-permission ve packer kanıtı.
- [ ] Authenticode trust-chain raporu ve offline iptal kısıtı.
- [ ] İmzalı offline kural paketi, downgrade protection, rollback.
- [ ] Parser bütçeleri ve fuzz testleri.

Sıra: M3 ölçüm/kalibrasyon → M4 yerel ML → M5 kısıtlı AI kanıt yorumlayıcısı → M6 izole davranış laboratuvarı → M7 kontrollü müdahale → M8 yayın sertleştirmesi. Sonraki aşamaya otomatik geçilmez.

## Oturum ve kapanış protokolü

1. `git status`, branch ve son commit'i kontrol et; kullanıcı değişikliklerini silme/resetleme.
2. Bu dosyada aktif platform ve ilk unchecked maddeyi doğrula; yalnız onu yap.
3. Kod, test, kanıt ve dokümanı birlikte güncelle; kapsam dışına sapma.
4. `git diff --check` ve ilgili testleri çalıştır; native kapsamı dürüstçe kaydet.
5. Bu dosyada durum, tamamlananlar, plan, tarih ve son commit'i güncelle.
6. Anlamlı commit oluşturup `git push origin main` yap; doğal durakta bekle ve kullanıcıya sonucu bildir.

## Ayrintili birlesik yol haritasi ve kabul kapilari

Bu bölüm, önceki genel ve Linux roadmap dosyalarındaki ayrıntıların tek kaynak halidir.

### Linux alt asamalari (L0-L7)

| Asama | Durum | Kapsam | Kapanis kaniti |
|---|---|---|---|
| L0 Baseline | Kod hazır, native kanıt bekliyor | Kernel/header, VM, BCC, tracefs, fanotify fotoğrafı | Gerçek Linux JSON snapshot |
| L1 Headers | Kod hazır, native apply bekliyor | Kernel-header eşleşmesi, VM conflict, dry-run/apply | Fixture ve rollback kanıtı |
| L2 fanotify | Kod hazır, native verify bekliyor | Permission event, mount, overflow/restart/timeout | Benign event ve root kanıtı |
| L3 eBPF | Kod hazır, native verify bekliyor | BCC/tracefs/header, filtreli olay, cleanup | Harmless event ve detach kanıtı |
| L4 pre-exec | Kod hazır, native verify bekliyor | FD/file identity, ortak scanner/scorer | Parity, TOCTOU ve bütçe testleri |
| L5 response | Kod hazır, native verify bekliyor | Hash-zincirli audit, karantina/restore | Audit, disk, izin testleri |
| L6 resilience | Kod hazır, native verify bekliyor | p50/p95, kaynak, event drop, fuzz/stres | Sürümlü benchmark |
| L7 release | Kod hazır, native verify bekliyor | Debian/Pardus paket, imza, SBOM, checksum | Native kapasite ve indirme kanıtı |

L0-L7 geçişi, önceki kapının test/kanıt/dokümanı tamamlanmadan yapılmaz. Windows portable testleri native Linux kanıtı değildir.

### Genel ürün asamalari (M1-M8)

- **M1 tamamlandı:** Ortak entropy/scanner/scorer, sınırlı PE kanıtı, INCONCLUSIVE sözleşmesi ve Windows monitor-only hattı.
- **M2 sıradaki:** Provenance'lı hash/signature, YARA-X değerlendirmesi, PE import/export ve section/packer kanıtı, Authenticode trust-chain, imzalı offline kural paketi, downgrade/rollback, parser bütçeleri ve fuzz.
- **M3:** Etiketli veri, leakage-resistant ayrım, precision/recall/false-positive/INCONCLUSIVE, gecikme ve kaynak ölçümü.
- **M4:** Cihaz içi küçük ML modeli, sürümlü feature schema, imzalı model ve deterministik fallback.
- **M5:** Ham dosyayı çalıştırmayan yerel AI kanıt yorumlayıcısı; şema, injection testleri ve bütçeler. AI tek başına müdahale kararı veremez.
- **M6:** Atılabilir VM, kontrollü ağ, host paylaşımı yok, davranış kanıtı ve snapshot temizleme.
- **M7:** Hızlı karar/derin analiz ayrımı, Linux fail-open/closed politikası, kimlik bağlı cache ve rollback testleri; Windows MONITOR_ONLY.
- **M8:** Fuzz/stres, SBOM/lisans, destek matrisi, kurulum-yükseltme-rollback, imzalı paket, checksum ve gerçek landing doğrulaması.

## Makine-okunur son durum

```json
{"schema":"elyra.ai-context.v2","updated":"2026-09-14","current_milestone":"M3_COMPLETE","next_milestone":"M4_ON_DEVICE_ML","last_commit":"9ca22b0","last_validation":"M3: 8 passed, 1 warning"}
```

```json
{"schema":"elyra.ai-context.v2","updated":"2026-09-14","current_milestone":"M3_MEASUREMENT_IN_PROGRESS","next_milestone":"M3_NATIVE_EVALUATION_REPORT","windows_status":"PAUSED_AT_W1","linux_status":"L7_COMPLETE_NATIVE_EVIDENCE_HOST_DEPENDENT","cloud_allowed":false,"trained_model_available":false,"llm_analyst_available":false,"last_commit":"02b0ece","last_validation":"signature/yara/authenticode: 11 passed; pe evidence: 59 passed, 1 skipped; calibration/dataset/metrics tests pending user run","m2_completed":["provenance-aware local rule bundle schema","bounded YARA-X adapter","bounded PE directory and packer evidence","honest Authenticode report","signature parser resource/fuzz safety"],"m3_completed":["deterministic local evaluation metrics","leakage-resistant dataset manifest validation","recommendation-only threshold calibration"]}
```
