import logging
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from .const import DOMAIN, CONF_MAC_ADDRESS
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["sensor", "binary_sensor", "button", "select"]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    address = entry.data[CONF_MAC_ADDRESS]
    device = MelittaDevice(address, entry.title, hass=hass)
    hass.data[DOMAIN][entry.entry_id] = device

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def _initial_connect():
        success = await device.connect()
        if not success:
            _LOGGER.info("Initial connect failed for %s, auto-reconnect will retry", address)
            device.schedule_reconnect()

    entry.async_create_background_task(hass, _initial_connect(), f"melitta_connect_{address}")

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    device: MelittaDevice = hass.data[DOMAIN].get(entry.entry_id)
    if device:
        _LOGGER.info("Unloading Melitta integration, disconnecting device...")
        await device.disconnect()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    _LOGGER.info("Removing Melitta integration entry for %s", entry.data.get(CONF_MAC_ADDRESS, "unknown"))
    device: MelittaDevice = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if device:
        await device.disconnect()
