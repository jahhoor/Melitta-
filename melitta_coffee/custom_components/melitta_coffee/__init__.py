import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall

from .const import DOMAIN, CONF_MAC_ADDRESS, CONF_DEVICE_NAME, BEVERAGE_MAP, STRENGTH_MAP
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [
    Platform.BUTTON,
    Platform.SENSOR,
    Platform.BINARY_SENSOR,
    Platform.SELECT,
]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    address = entry.data[CONF_MAC_ADDRESS]
    name = entry.data.get(CONF_DEVICE_NAME, "Melitta Koffiezetapparaat")

    device = MelittaDevice(address, name)
    hass.data[DOMAIN][entry.entry_id] = device

    try:
        await device.connect()
    except Exception as err:
        _LOGGER.warning("Initial connection to %s failed: %s. Will retry.", address, err)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def _update_device(_now=None):
        try:
            await device.update()
        except Exception as err:
            _LOGGER.debug("Update failed for %s: %s", address, err)

    entry.async_on_unload(
        hass.helpers.event.async_track_time_interval(
            _update_device,
            timedelta(seconds=30),
        )
    )

    async def handle_brew_service(call: ServiceCall) -> None:
        beverage = call.data.get("beverage", "coffee")
        strength = call.data.get("strength", "medium")
        cups = call.data.get("cups", 1)

        for dev_entry_id, dev in hass.data[DOMAIN].items():
            if isinstance(dev, MelittaDevice):
                await dev.brew(beverage, strength, cups)
                break

    hass.services.async_register(DOMAIN, "brew_coffee", handle_brew_service)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        device: MelittaDevice = hass.data[DOMAIN].pop(entry.entry_id)
        try:
            await device.disconnect()
        except Exception as err:
            _LOGGER.debug("Disconnect failed: %s", err)

    return unload_ok
