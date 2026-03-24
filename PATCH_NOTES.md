Melitta Bluetooth patch v2.0.4

Gerichte aanpassing op basis van dzerik/melitta-barista-ha:
- pairing wordt nu alleen gestart als dat echt nodig lijkt
- na herhaalde service-discovery/BlueZ-fouten controleert de integratie eerst of het apparaat al paired is
- alleen als er geen bond bestaat, probeert de integratie automatisch te pairen via D-Bus Agent1
- service-discovery fouten triggeren niet langer meteen RemoveDevice
- RemoveDevice blijft alleen als laatste redmiddel voor echte BlueZ busy/InProgress situaties
- eerste connect na Home Assistant start is teruggebracht naar 15s zodat pairing binnen de 60s connect-window van de machine beter haalbaar blijft

Testvolgorde:
1. sluit de Melitta app volledig af en zet Bluetooth op je telefoon tijdelijk uit
2. zet de machine op Verbinden / blauwe knippermodus
3. herstart Home Assistant
4. kijk of de status eerst naar pairing gaat en daarna naar ready
