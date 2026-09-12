# Phase 1 doğrulama kaydı

Tarih: 2026-09-11  
Kapsam: ortak Windows statik tarama temeli ve dürüst sonuç sözleşmesi

## Gerçekleştirilen kontroller

- Windows native test suite: **242 passed, 11 skipped**.
- Native `ReadDirectoryChangesW` entegrasyon testi: **1 passed**.
- Zararsız native smoke: `C:\Windows\py.exe` PE32/x86 (6 bölüm),
  `C:\Windows\System32\kernel32.dll` PE32+/x64 DLL (8 bölüm). Dosyalar
  çalıştırılmadan incelendi; statik tarama `OK`, MIME tutarlı, hata yok.
- Normal kullanıcı erişimiyle ortak otomatik/elle analiz: `ANALYZED`,
  `NO_HIGH_RISK_INDICATORS`, `enforced_action=NONE`.

## Atlanan kapsam

Windows'ta Linux'a özgü 17 test modülü toplanmaz. ELF, `/proc` fanotify,
POSIX symlink ve ayrıcalık isteyen testler de atlandı. Linux fanotify/eBPF canlı
kapasitesi bu Windows makinesinde çalıştırılmadı; uygun Linux hostta şu komut
gereklidir: `sudo PYTHONPATH=src python scripts/test_linux_capacity.py --live`.

## Güvenlik sınırları

PE parser yalnızca sınırlı DOS/COFF/optional header ve section metadata okur;
imza doğrulamaz, import/disassembly yapmaz ve kod yüklemez. Certificate table
varlığı Authenticode güveni değildir. PE anomalileri bu aşamada skora ağırlık
eklemez.

Windows izleyici `ReadDirectoryChangesW` veya açıkça enjekte edilen yerel ETW
adaptörüyle yalnızca gözlem yapar. `enforced_action=NONE` ve `MONITOR_ONLY`
bilinçli sözleşmedir; imzalı minifilter olmadan çalıştırma engellenmez.

Başarısız/kısmi/değişen/aşırı büyük/yönlendirilmiş dosya `INCONCLUSIVE` ve
nullable risk skoru ile raporlanır. 0–100 skor olasılık değildir. Bu aşamada
YARA, malware hash veritabanı, ML, LLM ve sandbox yoktur.

## Kapanış

Bu kayıt ve testler **Aşama 1 kabul kapısını karşılıyor**. Değişiklikler yerel
çalışma ağacındadır; GitHub'a push ayrı bir işlemdir. Aşama 2 başlatılmamıştır.
