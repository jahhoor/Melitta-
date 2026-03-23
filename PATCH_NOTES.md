# Melitta Bluetooth patch

Deze patch maakt de verbindingsflow dichter bij de Android app:

- geen automatische bond removal meer na auth failures
- geen `ServicesResolved`-check meer als criterium voor "stale bond"
- geen extra `Pair()`/"force encryption" stap meer na reconnect
- notifications lopen nu eerst via `Bleak.start_notify()`
- auth wacht nu eerst op notifications, en valt alleen terug op read polling als notify niet lukt
- `manifest.json` bevat nu ook `dbus-fast`
- `__init__.py` forceert niet langer altijd DEBUG logging

## Handmatig testen

1. Verwijder oude custom integratiebestanden in Home Assistant.
2. Pak deze zip uit zodat je `custom_components/melitta_coffee` krijgt.
3. Herstart Home Assistant.
4. Verwijder alleen handmatig een bestaande Bluetooth-koppeling als het apparaat echt in een rare staat blijft hangen.
5. Zet de machine in **Verbinden**-modus en voeg de integratie opnieuw toe.
