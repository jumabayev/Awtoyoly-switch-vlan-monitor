# Switch VLAN Monitor

Ofis switchlerini (Edge-Core, HP Comware, Cisco) telnet ile tarayip port/VLAN/MAC/IP bilgilerini gorsel olarak izleyen web uygulamasi.

![Python](https://img.shields.io/badge/Python-3.12-blue) ![Flask](https://img.shields.io/badge/Flask-3.1-green) ![Docker](https://img.shields.io/badge/Docker-ready-blue)

## Ozellikler

- **Canli Port Izleme** - Switch portlarinin UP/DOWN durumu, hiz, duplex
- **VLAN Haritasi** - Her portun VLAN atamasi, renkli gorsellestirme, 30+ farkli renk
- **MAC Adresleri** - Her porta bagli cihazlarin MAC adresleri
- **IP Cozumleme** - MAC adreslerinden IP ve hostname bilgisi (Windows DHCP Server + SonicWall DHCP + local ARP)
- **TX/RX Trafik** - Port bazli trafik istatistikleri (GB/MB/KB)
- **SQLite Veritabani** - Switch bilgileri kalici saklanir, sayfa yenilendiginde otomatik yuklenir
- **Docker Ready** - Tek komutla deploy
- **Multi-Switch** - Birden fazla switch ayni anda izlenebilir
- **Multi-Vendor** - Edge-Core ECS, HP/H3C Comware, Cisco IOS destegi

## Desteklenen Switchler

| Marka | Model | Protokol |
|-------|-------|----------|
| Edge-Core | ECS4510, ECS4620 vb. | Telnet |
| HP / H3C | A5800, Comware serisi | Telnet |
| Cisco | Catalyst 2960, 3750 vb. | Telnet |

## Kurulum

### Docker (Onerilen)

```bash
docker build -t switch-monitor .
docker run -d --name switch-monitor --restart unless-stopped -p 5050:5050 switch-monitor
```

Tarayicidan ac: `http://<sunucu-ip>:5050`

### Manuel

```bash
pip install -r requirements.txt
python app.py
```

## Yapilandirma

### IP Cozumleme Kaynaklari

Uygulama MAC adreslerini IP'ye cozumlemek icin 3 kaynak kullanir:

1. **Windows DHCP Server** - `app.py` icinde `get_dhcp_leases()` fonksiyonunda DHCP server IP/kullanici/sifre ayarlanir
2. **SonicWall DHCP** - SonicWall API uzerinden DHCP lease tablosu
3. **Local ARP** - Sunucunun kendi ARP tablosu

Bu kaynaklari yapilandirmak icin `app.py` dosyasindaki `get_dhcp_leases()` fonksiyonunu duzenleyin:

```python
# Windows DHCP Server
client = Client('DHCP_SERVER_IP', username='KULLANICI', password='SIFRE', ssl=False)

# SonicWall (opsiyonel)
s.post("https://SONICWALL_IP:444/api/sonicos/auth",
       json={"user": "admin", "password": "SIFRE"})
```

### Ortam Degiskenleri (Opsiyonel)

Hassas bilgileri `app.py` icinde degil, ortam degiskenleriyle de ayarlayabilirsiniz:

```bash
export DHCP_SERVER=10.10.11.245
export DHCP_USER=administrator
export DHCP_PASS=your_password
export SONICWALL_IP=172.20.10.254
export SONICWALL_USER=admin
export SONICWALL_PASS=your_password
```

## Kullanim

1. Tarayicidan `http://sunucu:5050` adresine gidin
2. Sol panelde switch IP, kullanici adi ve sifresini girin
3. Model secin (veya Otomatik Algilama birakin)
4. "Baglan & Tara" butonuna tiklayin
5. Port karelerine tiklayarak detay gorun (VLAN, MAC, IP, hostname, TX/RX)
6. VLAN etiketlerine tiklayarak filtreleme yapin

## Ekran Goruntusu

```
+----------------------------------+----------------------------------------+
|  Switch Ekle                     |  [Port Grid - Renkli VLAN haritasi]    |
|  IP: 10.10.10.198               |  1  2  3  4  5  6  7  8  9 10 11 12   |
|  User: admin                    |  13 14 15 16 17 18 19 20 21 22 23 24   |
|  Pass: ****                     |                                        |
|  [Baglan & Tara]                |  VLAN 39-ALIEN  VLAN 49-FINANCE  ...   |
|                                 |                                        |
|  > 10.10.10.195  Vty-0         |  Port Detay:                           |
|  > 10.10.10.197  Vty-1         |  Eth1/1 - Port 1 - UP                 |
|  > 10.10.10.198  Vty-0         |  VLAN: 49 (FINANCE) | Mode: ACCESS    |
|  > 10.10.10.199  Vty-0         |  TX: 443.4 GB | RX: 110.4 GB          |
|                                 |  MAC          IP             Hostname  |
|                                 |  E8-FF-1E-..  10.10.49.54   PC-FIN01 |
+----------------------------------+----------------------------------------+
```

## API

| Endpoint | Method | Aciklama |
|----------|--------|----------|
| `/` | GET | Web arayuzu |
| `/api/scan` | POST | Switch tara `{"ip","username","password","model"}` |
| `/api/switches` | GET | Kayitli switchleri listele |
| `/api/switches/<ip>` | DELETE | Switch sil |
| `/api/arp` | GET | Local ARP tablosu |

## Proje Yapisi

```
switch_monitor/
  app.py              # Flask backend + switch parsers
  requirements.txt    # Python bagimliliklari
  Dockerfile          # Docker build
  .dockerignore
  .gitignore
  templates/
    index.html        # Frontend (tek dosya, bagimliligi yok)
```

## Lisans

MIT
