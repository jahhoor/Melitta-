# Melitta Bluetooth Patch v2.0.2

Deze versie is aangepast op basis van de nieuwste Home Assistant log:
- `BleakClient.connect() called without bleak-retry-connector`
- herhaalde `failed to discover services, device disconnected`
- BlueZ fouten zoals `In Progress` en `br-connection-canceled`

## Belangrijkste wijzigingen
- directe `BleakClient.connect()` routes volledig verwijderd
- connect gebruikt nu alleen nog Home Assistant / `bleak-retry-connector` (`establish_connection`) met retries
- extra cooldown toegevoegd na mislukte service discovery of BlueZ-busy fouten
- langere connect-timeout en iets langere settle-delay na verbinden
- eerste automatische BLE connect na HA-opstart 12 seconden uitgesteld om startup-concurrentie te verminderen
- `bluetooth_adapters` toegevoegd aan de manifest dependencies
- manifest versie verhoogd naar `2.0.2`

## Waarom deze wijziging
Je log liet zien dat de vorige versie zichzelf nog in de weg zat:
- Home Assistant waarschuwde dat `BleakClient.connect()` zonder `bleak-retry-connector` werd gebruikt
- daarna volgden `failed to discover services` en BlueZ `In Progress` / `br-connection-canceled`

Deze patch probeert daarom minder agressief te verbinden en BlueZ meer tijd te geven om op te ruimen tussen pogingen.

## Testadvies
Installeer deze versie handmatig in `custom_components/melitta_coffee` en herstart Home Assistant volledig.
Sluit ook de officiële Melitta-app volledig af en zet Bluetooth op je telefoon tijdelijk uit tijdens het testen.

Gebruik deze logger-config tijdens testen:

```yaml
logger:
  default: warning
  logs:
    custom_components.melitta_coffee: debug
    bleak: debug
    bleak_retry_connector: debug
    habluetooth: debug
    homeassistant.components.bluetooth: debug
```
