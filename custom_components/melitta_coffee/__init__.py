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
    _LOGGER.info("SETUP: setting up Melitta integration for %s (title=%s, entry_id=%s)", address, entry.title, entry.entry_id)
    device = MelittaDevice(address, entry.title, hass=hass)
    hass.data[DOMAIN][entry.entry_id] = device

    _LOGGER.debug("SETUP: forwarding platform setups: %s", PLATFORMS)
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def _initial_connect():
        _LOGGER.info("SETUP: starting initial connection to %s", address)
        success = await device.connect()
        if success:
            _LOGGER.info("SETUP: initial connection succeeded for %s", address)
        else:
            _LOGGER.info("SETUP: initial connect failed for %s, scheduling auto-reconnect", address)
            device.schedule_reconnect()

    entry.async_create_background_task(hass, _initial_connect(), f"melitta_connect_{address}")
    _LOGGER.debug("SETUP: background connect task created for %s", address)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    address = entry.data.get(CONF_MAC_ADDRESS, "unknown")
    _LOGGER.info("UNLOAD: unloading Melitta integration for %s (entry_id=%s)", address, entry.entry_id)
    device: MelittaDevice = hass.data[DOMAIN].get(entry.entry_id)
    if device:
        _LOGGER.info("UNLOAD: disconnecting device %s...", address)
        await device.disconnect()
        _LOGGER.info("UNLOAD: device disconnected")

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    _LOGGER.info("UNLOAD: platform unload result=%s for %s", unload_ok, address)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    address = entry.data.get(CONF_MAC_ADDRESS, "unknown")
    _LOGGER.info("REMOVE: removing Melitta integration entry for %s (entry_id=%s)", address, entry.entry_id)
    device: MelittaDevice = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if device:
        _LOGGER.info("REMOVE: disconnecting device %s before removal", address)
        await device.disconnect()
        _LOGGER.info("REMOVE: device disconnected, entry removed")
