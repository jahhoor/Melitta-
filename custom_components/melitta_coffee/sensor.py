import logging

from homeassistant.components.sensor import SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, CONF_DEVICE_NAME, CONF_MODEL, CONF_MAC_ADDRESS
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    device: MelittaDevice = hass.data[DOMAIN][entry.entry_id]

    entities = [
        MelittaStatusSensor(device, entry),
        MelittaWaterLevelSensor(device, entry),
        MelittaBeanLevelSensor(device, entry),
        MelittaErrorSensor(device, entry),
        MelittaBeverageSensor(device, entry),
        MelittaTotalBrewsSensor(device, entry),
        MelittaLastConnectSensor(device, entry),
        MelittaLastErrorSensor(device, entry),
        MelittaBleDiscoverySensor(device, entry),
    ]

    async_add_entities(entities)


class MelittaBaseSensor(SensorEntity):

    _attr_has_entity_name = True

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        self._device = device
        self._entry = entry

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.data[CONF_MAC_ADDRESS])},
            name=self._entry.data.get(CONF_DEVICE_NAME, "Melitta"),
            manufacturer="Melitta",
            model=self._entry.data.get(CONF_MODEL, "Barista Smart"),
        )

    @property
    def available(self) -> bool:
        return True

    async def async_added_to_hass(self) -> None:
        self._device.register_callback(self._handle_update)

    async def async_will_remove_from_hass(self) -> None:
        self._device.remove_callback(self._handle_update)

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()


class MelittaStatusSensor(MelittaBaseSensor):

    STATUS_TRANSLATIONS = {
        "ready": "Klaar",
        "brewing": "Koffie zetten",
        "cleaning": "Reinigen",
        "descaling": "Ontkalken",
        "filter_insert": "Filter plaatsen",
        "filter_replace": "Filter vervangen",
        "filter_remove": "Filter verwijderen",
        "switch_off": "Uitschakelen",
        "easy_clean": "Snel reinigen",
        "intensive_clean": "Intensief reinigen",
        "evaporating": "Stoom",
        "busy": "Bezig",
        "offline": "Offline",
        "auth_failed": "Authenticatie mislukt",
    }

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_status"
        self._attr_name = "Status"
        self._attr_icon = "mdi:coffee-maker"

    @property
    def native_value(self) -> str:
        return self.STATUS_TRANSLATIONS.get(self._device.status, self._device.status)

    @property
    def extra_state_attributes(self) -> dict:
        attrs = {
            "status_intern": self._device.status,
            "process": self._device.process_state,
            "subprocess": self._device.subprocess_state,
            "progress": self._device.progress,
        }
        if self._device.status_raw:
            attrs["ruwe_data"] = self._device.status_raw
        if self._device.last_raw_status_hex:
            attrs["laatste_hex"] = self._device.last_raw_status_hex
        if self._device.version:
            attrs["firmware_versie"] = self._device.version
        return attrs


class MelittaWaterLevelSensor(MelittaBaseSensor):

    LEVEL_TRANSLATIONS = {
        "empty": "Leeg",
        "low": "Laag",
        "ok": "OK",
        "medium": "Gemiddeld",
        "full": "Vol",
        "unknown": "Onbekend",
    }

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_water_level"
        self._attr_name = "Waterstand"
        self._attr_icon = "mdi:water"

    @property
    def native_value(self) -> str:
        level = self._device.water_level
        translated = self.LEVEL_TRANSLATIONS.get(level)
        if translated:
            return translated
        return level


class MelittaBeanLevelSensor(MelittaBaseSensor):

    LEVEL_TRANSLATIONS = {
        "empty": "Leeg",
        "low": "Laag",
        "ok": "OK",
        "medium": "Gemiddeld",
        "full": "Vol",
        "unknown": "Onbekend",
    }

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_bean_level"
        self._attr_name = "Bonenvoorraad"
        self._attr_icon = "mdi:seed"

    @property
    def native_value(self) -> str:
        level = self._device.bean_level
        translated = self.LEVEL_TRANSLATIONS.get(level)
        if translated:
            return translated
        return level


class MelittaErrorSensor(MelittaBaseSensor):

    ERROR_TRANSLATIONS = {
        "brewing_unit_removed": "Zetgroep verwijderd",
        "drip_tray_missing": "Lekbak ontbreekt",
        "empty_drip_tray": "Lekbak legen",
        "fill_water": "Water bijvullen",
        "close_powder_lid": "Poederdeksel sluiten",
        "fill_powder": "Poeder bijvullen",
    }

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_error"
        self._attr_name = "Foutmelding"
        self._attr_icon = "mdi:alert-circle"

    @property
    def native_value(self) -> str | None:
        if self._device.error:
            return self.ERROR_TRANSLATIONS.get(
                self._device.error, self._device.error
            )
        return "Geen"


class MelittaBeverageSensor(MelittaBaseSensor):

    BEVERAGE_TRANSLATIONS = {
        "espresso": "Espresso",
        "ristretto": "Ristretto",
        "lungo": "Lungo",
        "espresso_doppio": "Dubbele Espresso",
        "ristretto_doppio": "Dubbele Ristretto",
        "cafe_creme": "Caf\u00e9 Cr\u00e8me",
        "cafe_creme_doppio": "Dubbele Caf\u00e9 Cr\u00e8me",
        "americano": "Americano",
        "americano_extra": "Americano Extra",
        "long_black": "Long Black",
        "red_eye": "Red Eye",
        "black_eye": "Black Eye",
        "dead_eye": "Dead Eye",
        "cappuccino": "Cappuccino",
        "espresso_macchiato": "Espresso Macchiato",
        "caffe_latte": "Caff\u00e8 Latte",
        "cafe_au_lait": "Caf\u00e9 au Lait",
        "flat_white": "Flat White",
        "latte_macchiato": "Latte Macchiato",
        "latte_macchiato_extra": "Latte Macchiato Extra",
        "latte_macchiato_triple": "Latte Macchiato Triple",
        "milk": "Warme Melk",
        "milk_froth": "Melkschuim",
        "hot_water": "Heet Water",
        "freestyle": "Freestyle",
    }

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_beverage"
        self._attr_name = "Huidig drankje"
        self._attr_icon = "mdi:cup"

    @property
    def native_value(self) -> str | None:
        if self._device.current_beverage:
            return self.BEVERAGE_TRANSLATIONS.get(
                self._device.current_beverage, self._device.current_beverage
            )
        return "Geen"


class MelittaTotalBrewsSensor(MelittaBaseSensor):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_total_brews"
        self._attr_name = "Totaal gezet"
        self._attr_icon = "mdi:counter"

    @property
    def native_value(self) -> int:
        return self._device.total_brews


class MelittaLastConnectSensor(MelittaBaseSensor):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_last_connect"
        self._attr_name = "Laatste verbinding"
        self._attr_icon = "mdi:clock-check-outline"

    @property
    def native_value(self) -> str | None:
        return self._device.last_connect_time or "Nooit verbonden"


class MelittaLastErrorSensor(MelittaBaseSensor):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_last_error"
        self._attr_name = "Laatste fout"
        self._attr_icon = "mdi:alert-outline"

    @property
    def native_value(self) -> str | None:
        return self._device.last_error_message or "Geen"

    @property
    def extra_state_attributes(self) -> dict:
        attrs = {}
        if self._device.last_write_result:
            attrs["laatste_schrijfresultaat"] = self._device.last_write_result
        return attrs


class MelittaBleDiscoverySensor(MelittaBaseSensor):

    def __init__(self, device: MelittaDevice, entry: ConfigEntry) -> None:
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_ble_discovery"
        self._attr_name = "BLE Diagnostiek"
        self._attr_icon = "mdi:bluetooth-settings"
        self._attr_entity_category = EntityCategory.DIAGNOSTIC

    @property
    def native_value(self) -> str:
        info = self._device.discovered_services_info
        if len(info) > 255:
            lines = info.split("\n")
            summary_parts = []
            for line in lines:
                if line.startswith("Geselecteerd") or line.startswith("Schrijfbare") or line.startswith("Leesbare") or line.startswith("Notificatie"):
                    summary_parts.append(line)
            if summary_parts:
                return " | ".join(summary_parts)
            return info[:255]
        return info

    @property
    def extra_state_attributes(self) -> dict:
        attrs = {
            "volledige_info": self._device.discovered_services_info,
            "services_gevonden": self._device.services_discovered,
            "mac_adres": self._device.address,
            "geauthenticeerd": self._device.is_authenticated,
            "ble_verbonden": self._device.is_ble_connected,
        }

        notifications = self._device.raw_notifications
        if notifications:
            attrs["aantal_notificaties"] = len(notifications)
            recent = notifications[-5:] if len(notifications) > 5 else notifications
            for i, notif in enumerate(recent):
                idx = len(notifications) - len(recent) + i
                attrs[f"notificatie_{idx}"] = f"{notif['time']}: {notif['hex']}"

        if self._device.last_write_result:
            attrs["laatste_schrijfresultaat"] = self._device.last_write_result

        return attrs
