import asyncio
import logging
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.event import async_track_time_interval

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

    device = MelittaDevice(address, name, hass=hass)
    hass.data[DOMAIN][entry.entry_id] = device

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    async def _update_device(_now=None):
        try:
            await device.update()
        except Exception as err:
            _LOGGER.debug("Update failed for %s: %s", address, err)

    entry.async_on_unload(
        async_track_time_interval(
            hass,
            _update_device,
            timedelta(seconds=30),
        )
    )

    hass.async_create_task(_update_device())

    async def handle_brew_service(call: ServiceCall) -> None:
        beverage = call.data.get("beverage", "coffee")
        strength = call.data.get("strength", "medium")
        cups = call.data.get("cups", 1)

        for dev_entry_id, dev in hass.data[DOMAIN].items():
            if isinstance(dev, MelittaDevice):
                await dev.brew(beverage, strength, cups)
                break

    if not hass.services.has_service(DOMAIN, "brew_coffee"):
        hass.services.async_register(DOMAIN, "brew_coffee", handle_brew_service)

    _LOGGER.info("Melitta Coffee integration setup complete for %s (%s)", name, address)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    if unload_ok:
        device: MelittaDevice = hass.data[DOMAIN].pop(entry.entry_id, None)
        if device:
            try:
                await asyncio.wait_for(device.disconnect(), timeout=15.0)
            except asyncio.TimeoutError:
                _LOGGER.warning("Disconnect timed out for %s, forcing cleanup", entry.entry_id)
            except Exception as err:
                _LOGGER.debug("Disconnect failed: %s", err)

        if not hass.data[DOMAIN]:
            if hass.services.has_service(DOMAIN, "brew_coffee"):
                hass.services.async_remove(DOMAIN, "brew_coffee")

    return unload_ok


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    device: MelittaDevice = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if device:
        try:
            await asyncio.wait_for(device.disconnect(), timeout=15.0)
        except asyncio.TimeoutError:
            _LOGGER.warning("Disconnect timed out during removal for %s, forcing cleanup", entry.entry_id)
        except Exception as err:
            _LOGGER.debug("Disconnect on remove failed: %s", err)

    dev_reg = dr.async_get(hass)
    address = entry.data.get(CONF_MAC_ADDRESS, "")
    devices = dr.async_entries_for_config_entry(dev_reg, entry.entry_id)
    for dev_entry in devices:
        _LOGGER.info(
            "Removing device %s (%s) from device registry",
            dev_entry.name, address,
        )
        dev_reg.async_remove_device(dev_entry.id)

    if not hass.data.get(DOMAIN):
        if hass.services.has_service(DOMAIN, "brew_coffee"):
            hass.services.async_remove(DOMAIN, "brew_coffee")

    _LOGGER.info("Melitta Coffee integration removed for %s", address)
