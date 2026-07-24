# MakimaCodex

## Faz Adımları

### Faz 0 — Temel Güvenlik ve Sınırlar

- Rol, ajan, çalışma zamanı, sağlayıcı, model ve hesap kimlikleri ayrıldı.
- Sürümlü görev sözleşmesi ve varsayılan olarak reddeden izin sistemi oluşturuldu.
- Gizli bilgileri reddeden bellek politikası ve güvenli geliştirme sınırları tanımlandı.

### Faz 1 — Kalıcı Görev ve Kanıt Omurgası

- Görev, sözleşme, iş akışı, politika, kanıt ve karar yaşam döngüleri oluşturuldu.
- Değiştirilemez olay geçmişi, bütünlük zinciri, SQLite saklama ve içerik adresli artefakt sistemi eklendi.
- Görev, kanıt, karar, zaman çizelgesi ve bütünlük komutları hazırlandı.

### Faz 2 — Güvenli Tek Ajan Yürütme

- Onaylı görevlerin sınırlandırılmış bir kodlama ajanı tarafından çalıştırılması sağlandı.
- İzole çalışma ağacı, süreç denetimi, yetenek kontrolü, yeniden deneme ve kurtarma mekanizmaları eklendi.
- Çalıştırma manifesti, gözlemlenebilir olaylar ve mekanik doğrulama sistemi oluşturuldu.

### Faz 3 — Bağımsız İnceleme ve Yönetişim

- Bağımsız inceleyiciler, bulgu doğrulama, çoğunluk değerlendirmesi ve deterministik karar sistemi eklendi.
- İncelemeler ağ erişimi kapalı, salt okunur ve sınırlandırılmış ortamlarda çalıştırıldı.
- Onarım önerisi, yeniden inceleme, feragat ve insan onayı kayıtları oluşturuldu.

### Faz 4 — Model Zekâsı ve Yeterlilik

- Model keşfi, uyumluluk kontrolleri, benchmark çalıştırmaları ve rol bazlı puan kartları eklendi.
- Model, çalışma zamanı, araçlar, bağlam ve ortam birlikte sürümlü yürütme yapılandırması olarak değerlendirildi.
- Güvensiz yapılandırmalar için karantina, süre sonu ve yeniden yeterlilik kuralları oluşturuldu.

### Faz 5 — Yönlendirme ve Takım Oluşturma

- Görev parmak izi, rol bağımlılık grafiği ve takım planı oluşturma sistemi eklendi.
- Yeterli modellerin politika, risk, gizlilik, bütçe ve kapasiteye göre seçilmesi sağlandı.
- Sabitlenmiş yönlendirme planları, yürütme bağları, yapılandırılmış devir paketleri ve geri dönüş yolları eklendi.

### Faz 6 — Katmanlı Memory OS

- Yerel öncelikli, kapsam kontrollü, sürümlü ve kaynağı izlenebilir temel Memory OS dikey dilimi oluşturuldu.
- Yazma öncesi gizli bilgi temizleme, güven sınırları, açıklanabilir geri çağırma ve yaklaşık bağlam bütçeleme eklendi.
- Outbox ingestion, gerçek embedding, plugin backend, backup/encryption, legal purge ve tam hygiene incrementleri devam ediyor.

## Son Yapılan

- Faz 6.0.1 hardening paketi uygulandı.
- Memory injection, `PREPARED → runtime ACK → DELIVERED` protokolüne geçirildi.
- Otomatik üretim enjeksiyonu, çalışma zamanı teslim makbuzu sisteme bağlanana kadar kapalı tutuldu.
- Boş rol ACL deny-all yapıldı; bitemporal validity, retrieval portları ve soft-forget effective state düzeltildi.
- Güvenilmeyen indeks kayıtları kanonik depodan yeniden doğrulanıyor; gizli çatışmalar kimlik sızdırmadan işaretleniyor.
- GitHub doğrulamasına zorunlu Docker sandbox kabulü ve iki koşunun birebir çıktı karşılaştırması eklendi.
- Faz 6 temel dikey dilimi koşullu kabul edildi; tam Faz 6 henüz tamamlanmadı.
