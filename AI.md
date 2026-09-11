# ELLIOT AI handoff index

Bu dosya, GitHub ana sayfasında görülebilen kısa devam noktasıdır. Yeni bir AI
önce bunu, sonra bağlantılı ayrıntılı belgeleri okumalıdır.

## Durum

- Windows geliştirmesi **DURAKLATILDI**. Son nokta: W1 ortak Windows statik
  analiz temeli tamamlandı; Windows `ReadDirectoryChangesW` bildirimleri manuel
  taramayla aynı statik taramayı kullanıyor. Windows `MONITOR_ONLY` ve
  `enforced_action=NONE` olarak kalır.
- Linux geliştirmesi **L2 UYGULAMASI HAZIR, NATIVE KANIT BEKLENİYOR**. fanotify
  capability raporu descriptor açmadan eklendi; native root enforcement kanıtı
  bu Windows oturumunda alınmadı. L3'e geçilmez.
- Ortak kodlar `src/elliot/analyzer`, `scoring`, `gui` ve uygun servis katmanında
  kalır. OS’ye özgü kodlar `src/elliot/monitor/fanotify`, `ebpf` ve `windows`
  altındadır; yapay klasör ayrımı yapılmaz.

## Önce okunacak belgeler

1. [ELLIOT_AI_CONTEXT.md](ELLIOT_AI_CONTEXT.md) — tam mimari, geçmiş ve devam protokolü
2. [ELLIOT_LINUX_ROADMAP.md](ELLIOT_LINUX_ROADMAP.md) — yalnız Linux planı
3. [ELLIOT_ROADMAP.md](ELLIOT_ROADMAP.md) — genel sekiz aşama ve güvenlik sınırları
4. [Phase 1 verification](SIPER-stage15.3/docs/phase1-verification.md) — Windows kabul kanıtı
5. [README.md](README.md) — kullanıcıya dönük giriş ve çalıştırma bilgisi

## Windows W1 handoff — burada devam edilmeyecek

Tamamlandı: ortak Windows scanner/scorer, bounded entropy/PE header-section
evidence, nullable `INCONCLUSIVE`, local path/reparse/queue/retry controls,
GUI `N/A`, native notification parity tests, README/context/roadmap. Test kanıtı:
243 passed, 11 skipped; 1 native ReadDirectoryChangesW integration passed.

Daha sonra yapılacak Windows işleri: reparse/handle yaşam döngüsünü ayrı native
güvenlik incelemesiyle sertleştirme, yerel imza/hash kuralları, Authenticode
trust reporting, PE imports/packer evidence, ölçüm, ML/AI ve imzalı minifilter.
Bunlar şu anda yapılmayacak ve Linux çalışmasını bekletmeyecek.

## Linux başlangıç noktası

`ELLIOT_LINUX_ROADMAP.md` içindeki L0’dan başlanır: `scripts/linux_baseline.py`
ile native Linux ortamı,
çalışan kernel/header/BCC/tracefs/fanotify yetenek fotoğrafı ve mevcut test
sonuçları. L0 kapanmadan L1–L7’ye geçilmez. Her L aşaması doğal durakta test,
kanıt, doküman, commit ve push ile kapatılır.

## Değişiklik protokolü

Yeni AI `git status` ile başlar; kullanıcıya ait değişiklikleri silmez. Yalnız
aktif platform planındaki ilk unchecked işi yapar. Zararlı dosya indirme/çalıştırma,
bulut telemetrisi, sahte başarı yüzdesi ve tamamlanmamış analizi “temiz” saymak
yasaktır. Doğal durakta ilgili markdown durumlarını günceller, testleri çalıştırır,
commit/push yapar ve rapor verip bekler.
