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
