# Elyra AI çalışma alanı

Bu klasör, projenin tüm yapay zekâ ve makine öğrenmesi çalışmalarının tek üst
başlığıdır. Ham dosya çalıştırma, bulut API'si, uzaktan telemetri ve otomatik
silme burada da yasaktır.

## Alt alanlar

- `models/`: sürümlü, cihaz-içi model manifestleri (imzalı paket gelene kadar örnek şemalar).
- `schemas/`: özellik ve AI kanıt sözleşmeleri.
- `experiments/`: yalnızca yasal/sentetik veriyle tekrarlanabilir deney kayıtları.
- `reports/`: ölçüm ve kalibrasyon çıktıları.

Çalıştırılabilir Python kodu `elyra-engine/src/elyra/ai/` altındadır; Python paket
adlarında nokta kullanılamadığı için bu ayrım kasıtlıdır.

## Aşamalar

1. M4: cihaz-içi ML özellik şeması, model bütünlüğü ve deterministik fallback.
2. M5: kanıt özetlerini yorumlayan, ham dosyayı çalıştırmayan yerel AI adapteri.

Model sonucu tek başına karantina/silme veya kernel kararı veremez. Model yokluğu,
bozuk manifest veya zaman aşımı `UNAVAILABLE`/`INCONCLUSIVE` olarak raporlanır.
## Kurulabilir AI asistanı

Elyra'nın sohbet katmanı doğrudan uygulamanın içine bağlanır. Ollama, harici
sunucu veya bulut API'si kullanılmaz. GGUF model dosyası
`%USERPROFILE%/.elyra/models/chat/model.gguf` (Windows) ya da
`~/.elyra/models/chat/model.gguf` (Linux) konumundan yüklenir. Model henüz
kurulu değilse güvenlik kanıtı analizleri çalışmaya devam eder ve sohbet alanı
modelin eksik olduğunu açıkça bildirir.

İlk çalıştırmada **Yerel modeli kur** düğmesi yaklaşık 1,1 GB olan Qwen2.5
1.5B Instruct GGUF Q4_K_M modelini indirir. Model uygulama içindeki gömülü
runtime tarafından yüklenir; ayrı Ollama veya sunucu kurulmaz. Model lisansı
Apache-2.0'dır. Kaynak model: https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF

GitHub Release ile yayımlanan `elyra-ai-linux_<version>-1_amd64.deb` paketi
yerel `elyra-ai` komutunu ve masaüstü girişini kurar:

```bash
sudo apt install ./elyra-ai-linux_<version>-1_amd64.deb
elyra-ai --evidence ./evidence.json
```

İlk sürüm kanıtla sınırlıdır; dosya çalıştırmaz, karantina politikası değiştirmez
ve buluta veri göndermez. Çalışan kaynak kodun tek kopyası
`../elyra-engine/src/elyra/ai/` altında tutulur.
