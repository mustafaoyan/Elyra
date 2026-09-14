# Elyra veri kataloğu

Tüm modelleme verileri bu klasör altında, kaynak türü ve veri seti sürümüne göre tutulur.

```text
elyra.ai/data/
├── synthetic/
│   └── v1/
│       ├── samples.jsonl
│       ├── manifest.json
│       └── generation-report.json
└── real/
    └── README.md
```

## Sentetik veri

`synthetic/v1/` içeriği çalıştırılamaz, statik özellik tabanlı ve tamamen sentetik
10.000 kayıtlık veri setidir. Gerçek malware veya executable payload içermez.
`inconclusive` kayıtlar supervised eğitimden ayrı tutulur.

## Gerçek veri

Gerçek örnekler daha sonra `real/<version>/` altında ayrı manifest, provenance,
lisans ve saklama politikasıyla eklenecektir. Gerçek ve sentetik kayıtlar aynı
eğitim çalışmasında açıkça belirtilmeden birleştirilmeyecektir. Gizli, kişisel veya
lisanssız veriler repoya konulmaz.
