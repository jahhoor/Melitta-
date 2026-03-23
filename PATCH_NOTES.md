# Melitta Bluetooth Patch v2.0.1

Deze versie is aangepast op basis van:
- de Home Assistant log (`failed to discover services, device disconnected`)
- de APK-flow van de officiële Android-app (eerst gewone GATT connect, daarna notify op AD02, daarna `HU` auth)

## Belangrijkste wijzigingen
- automatische BlueZ `Pair()` / `force disconnect` stap uit de standaard connect-flow gehaald
- BLE connect probeert nu eerst een **rechte BleakClient connect** in plaats van direct `establish_connection(... max_attempts=3)`
- extra fallback-strategieën toegevoegd:
  - direct via `BLEDevice`
  - Home Assistant `establish_connection` met 1 poging
  - direct via het MAC-adres
- na connect iets langere rusttijd voordat notify/auth start
- auth probeert nu eerst **plaintext `HU`** en daarna pas encrypted fallback
- manifest versie verhoogd naar `2.0.1`

## Testadvies
Installeer deze versie handmatig in `custom_components/melitta_coffee` en herstart Home Assistant volledig.
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

## Verwachting
Deze patch richt zich vooral op het stuk dat in jouw log faalt: **service discovery tijdens connect**.
