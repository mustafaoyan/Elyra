# ELLIOT Linux geliştirme yol haritası

<!-- ELLIOT_LINUX_ROADMAP:v1 | status:L7_RELEASE_GATE_READY | updated:2026-09-11 -->

Bu belge yalnızca Linux/Pardus geliştirmesinin sıradaki işlerini tanımlar.
Kullanıcı açıkça **“başla”** demeden hiçbir Linux kodu, kernel ayarı veya canlı
kapasite testi değiştirilmeyecek. Her alt aşama bir doğal duraktır: test,
kanıt ve dokümantasyon tamamlanır; commit/push yapılır; sonra beklenir.

## Linux'a özel güvenlik sınırları

- Bulut yönetimi, uzaktan günlükleme ve dosya yükleme yoktur.
- fanotify/eBPF kapasitesi yalnızca uygun Linux kernelinde, yetkili kullanıcıyla
  doğrulanır; Windows test sonucu Linux kanıtı sayılamaz.
- Kernel callback içinde uzun AI/LLM/sandbox bekletilmez.
- Yüksek entropi kanıt olabilir; tek başına zararlı veya `DENY` kanıtı değildir.
- Fail-open/fail-closed davranışı varsayılanla gizlenmez; politika ve gecikme
  görünür bir sözleşmeyle seçilir.
- Canlı zararlı çalıştırılmaz. Testler sentetik, benign veya izole laboratuvar
  girdileriyle yapılır.

## L0 — Hazırlık ve mevcut Linux durumunun fotoğrafı

**Durum: UYGULAMASI HAZIR — LINUX NATIVE KANITI BEKLENİYOR.**

- Linux/Pardus sürümü, çalışan kernel, header yolu, BCC/tracefs/fanotify
  yetkileri ve sanallaştırma bilgilerini yalnız yerel kanıt dosyasına yaz.
- Mevcut unit testleri, portable capacity testini ve kurulum/preflight
  kontrollerini Linux native ortamında çalıştır; Windows sonuçlarını karıştırma.
- Destek matrisi ve beklenen `READY/DEGRADED/UNAVAILABLE` durumlarını dondur.
- `scripts/linux_baseline.py` ile paket kurmadan, probe bağlamadan ve fanotify
  grubu açmadan makine-okunabilir ortam fotoğrafı üret.

Kabul: Linux native ortam fotoğrafı + tekrar üretilebilir komutlar + bilinen
eksik yetkiler. Bu Windows çalışma makinesinde yalnız script ve sözleşme testi
doğrulanabilir; L0, Linux çıktısı alınana kadar **tamamlanmış sayılmaz**.

## L1 — Kernel header ve VM uyumluluğu

**Durum: UYGULAMASI HAZIR — NATIVE LINUX KANITI BEKLENİYOR. Bağımlılık: L0 sözleşmesi.**

- Çalışan kernel sürümü ile header/build ağacını karşılaştır; VirtualBox veya
  başka VM'de eski/mis-yönlendirilmiş bağları teşhis et.
- Çözüm planını varsayılan olarak dry-run üret; `--apply` yalnız root, tam yol
  doğrulaması ve açık kullanıcı çalıştırmasıyla paket kurup yapılandırabilsin.
- `VIRTUALIZED_HEADER_CONFLICT` durumunu açıkça raporla; gerçek dosya/klasörleri
  otomatik ezme ve kernel release değerini paket komutuna güvenli biçimde geçir.
- Exact-version yerel header bulunursa build symlink'ini atomik olarak düzelt;
  bulunamazsa dağıtımın uygun paket komutunu yalnız plan olarak göster.

Kabul: mismatch/VM fixture testleri, güvenli paket-komut testi ve dry-run çıktısı.
Native Linux'ta `--apply` çalıştırılması bu Windows oturumunda yapılmamıştır.
- Başarısız paket yöneticisi, internet yokluğu, header yokluğu ve sürüm
  uyuşmazlığını simüle eden testler ekle. Sistem build dizinini sessizce silme.

Kabul: gerçek çalışan kernel için doğru plan; dry-run değişiklik yapmaz; apply
öncesi/sonrası doğrulama ve geri dönüş adımları belgelenir.

## L2 — fanotify güvenilirlik temeli

**Durum: PLANLANDI. Bağımlılık: L0–L1.**

- fanotify başlatma, mark/permission event maskesi, mount kapsamı ve descriptor
  yaşam döngüsünü kernel sürümleriyle doğrula.
- Yetki eksikliği, queue overflow, descriptor hatası, daemon yeniden başlatma,
  dosya değişme yarışı ve geciken analiz için açık capability durumları üret.
- Permission callback içinde yalnız sınırlı, hızlı ve deterministic karar yolu
  kullan; uzun statik taramayı güvenli politika ile ayır.
- Fail-open/fail-closed seçimini kullanıcı politikasına bağla; güvenliymiş gibi
  varsayılan sessiz fallback yapma.

Kabul: benign dosya erişimi ve sentetik event akışı; overflow/restart/timeout
testleri; gerçek enforcement iddiası yalnız native root testinde.

L2 uygulaması: `assess_fanotify_capability()` descriptor açmadan Linux,
fanotify kernel girdisi, permission API'si ve root/CAP_SYS_ADMIN gereksinimlerini
`READY/DEGRADED/UNAVAILABLE` olarak raporlar. Native root enforcement testi bu
Windows oturumunda çalıştırılmadı.

## L3 — eBPF/tracefs gözlem hattı

**Durum: PLANLANDI. Bağımlılık: L1.**

- BCC probe derleme, tracefs/BTF/header uyuşmazlığı ve VirtualBox kısıtlarını
  capability raporuyla ayır.
- Process, write, rename ve seçilmiş network olaylarını filtrele; payload,
  credential veya uzak telemetri toplamayıp yerel bounded event şeması kullan.
- Probe attach başarısızlığı, ring/perf buffer overflow ve detach/cleanup
  yollarını test et; kernel panik riskini azaltmak için en küçük probe setiyle başla.
- eBPF gözlemini fanotify kararından ayrı sensör durumu olarak göster.

Kabul: harmless loopback ve benign process/file eventleri; overflow/cleanup;
kernel sürümü ve BCC sürümü kanıtı. “100% kapasite” yalnız ölçülen kapsam için
ifade edilir, tüm tehditlerin yakalanması anlamına gelmez.

L3 uygulaması: `assess_ebpf_capability()` BCC, tracefs, matching headers ve
privilege koşullarını probe attach etmeden raporlar; `EBPFLoader.capability()`
servis/GUI için aynı yerel capability sözleşmesini sunar. Native kernel telemetry
testi bu Windows oturumunda çalıştırılmadı.

## L4 — Ortak Linux pre-execution analiz hattı

**Durum: PLANLANDI. Bağımlılık: L2–L3.**

- fanotify eventinden doğrulanmış file identity/fd ile ortak `StaticFileScanner`
  ve `PreExecutionScoringEngine` çağır; path-only TOCTOU'yu azalt.
- Entropi, ELF, MIME, permission/path ve ilerideki kanıtları tek sonuç sözleşmesine
  taşı; ikinci entropi formülü veya sınırsız dosya okuması ekleme.
- Analiz `INCONCLUSIVE` olduğunda güvenli davranışı ve GUI/audit görünürlüğünü
  açıkça tanımla. Score olasılık değildir.
- Her karar için kural kimliği, kanıt, politika sürümü, dosya hash/identity ve
  gecikme kaydedilebilir yerel audit kaydı üret.

Kabul: event/manual parity, fd identity yarış testleri, boyut/zaman bütçesi,
karar gecikmesi ve fail policy testleri.

## L5 — Yerel audit, karantina ve geri alma

**Durum: PLANLANDI. Bağımlılık: L4.**

- Mevcut hash-zincirli yerel audit ve karantina bileşenlerini pre-execution
  sonuçlarıyla bağla; kayıt bütünlüğünü ve izinlerini doğrula.
- Müdahale varsayılanı silme değil, yetkili ve geri alınabilir karantina olsun.
  Restore öncesi içerik hash'i, hedef çakışması ve kullanıcı yetkisini kontrol et.
- Audit yazılamazsa bu durum koruma durumu olarak görünür; kayıt varmış gibi
  davranma.

Kabul: benign restore, çakışma, disk doluluğu, izin ve audit zinciri bozulma
testleri; destructive action yalnız açık test policy'si ile.

## L6 — Ölçüm, dayanıklılık ve performans

**Durum: PLANLANDI. Bağımlılık: L2–L5.**

- Linux native ölçüm seti: precision/recall ancak etiketli yasal veriyle;
  yanlış pozitif, kararsız oranı, event drop, p50/p95 gecikme, CPU/bellek.
- Kernel header varyantları, VM, event storm, büyük/değişen dosya, process
  churn, daemon crash/restart ve permission boundary testleri.
- Parser fuzz ve resource budget testlerini zararsız byte dizileriyle yürüt.
- Threshold kalibrasyonu yapılmadan olasılık veya zero-day başarı yüzdesi iddia etme.

Kabul: sürümlü dataset/manifest, tekrar üretilebilir benchmark ve hata raporu.

## L7 — Linux yayın kapısı

**Durum: PLANLANDI. Bağımlılık: L6.**

- Debian/Pardus paketini native Linux'ta üret, bağımlılıklarını sabitle, SBOM
  ve checksum oluştur; imzalama yapılmadan indirme sayfasına bağlama.
- Kurulum/kaldırma/yükseltme, systemd yetkileri, kernel uyumsuzluğu ve güvenli
  geri dönüşü temiz VM'de doğrula.
- Linux canlı capacity kanıtını JSON olarak kaydet; fanotify/eBPF/headers için
  ayrı sonuçlar ve sınırlamalar yayınla.
- Başarılı release sonrası landing download yapılandırmasını gerçek assetlere
  güncelle. Yer tutucu linkleri yayınlanmış paket diye göstermeme.

## İzleme JSON'u

```json
{
  "schema": "elliot.linux-roadmap.v1",
  "platform": "LINUX",
  "status": "L7_RELEASE_GATE_READY_NATIVE_EVIDENCE_PENDING",
  "current_milestone": "L7_LINUX_RELEASE_GATE",
  "windows_work": "PAUSED_AT_W1_HANDOFF",
  "start_keyword_required": true,
  "cloud_allowed": false,
  "live_malware_execution": false,
  "next_natural_stop": "L0 native baseline evidence",
  "completed": [],
  "todo": ["L0_NATIVE_EVIDENCE", "L1_NATIVE_APPLY_VERIFY", "L2_NATIVE_VERIFY", "L3_NATIVE_VERIFY", "L4_NATIVE_VERIFY", "L5_NATIVE_VERIFY", "L6_NATIVE_VERIFY", "L7_NATIVE_RELEASE_VERIFY"]
}
```

Her Linux alt aşaması tamamlandığında `completed` listesine taşınır, test ve
kanıt dosyası eklenir, commit/push yapılır ve çalışma durur. Kullanıcı “başla”
demeden bu listedeki kod işlerine başlanmaz.
