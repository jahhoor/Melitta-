"""The Melitta Barista Smart integration."""

from __future__ import annotations

import asyncio
import logging

from homeassistant.components import bluetooth
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_ADDRESS, CONF_NAME, Platform
from homeassistant.core import HomeAssistant, callback

from .ble_client import MelittaBleClient
from .const import (
    CONF_BLE_CONNECT_TIMEOUT,
    CONF_FRAME_TIMEOUT,
    CONF_MAX_CONSECUTIVE_ERRORS,
    CONF_POLL_INTERVAL,
    CONF_RECIPE_RETRIES,
    CONF_RECONNECT_DELAY,
    CONF_RECONNECT_MAX_DELAY,
    DEFAULT_BLE_CONNECT_TIMEOUT,
    DEFAULT_FRAME_TIMEOUT,
    DEFAULT_MAX_CONSECUTIVE_ERRORS,
    DEFAULT_POLL_INTERVAL,
    DEFAULT_RECIPE_RETRIES,
    DEFAULT_RECONNECT_DELAY,
    DEFAULT_RECONNECT_MAX_DELAY,
    DOMAIN,
)

_LOGGER = logging.getLogger("melitta_barista")

PLATFORMS: list[Platform] = [
    Platform.SENSOR,
    Platform.BUTTON,
    Platform.SELECT,
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Melitta Barista Smart from a config entry."""
    address: str = entry.data[CONF_ADDRESS]
    device_name: str | None = entry.data.get(CONF_NAME)

    _LOGGER.info(
        "Setting up Melitta Barista for %s (%s)", device_name or "unknown", address
    )

    ble_device = None
    try:
        ble_device = bluetooth.async_ble_device_from_address(
            hass, address.upper(), connectable=True
        )
        if ble_device is None:
            ble_device = bluetooth.async_ble_device_from_address(
                hass, address, connectable=True
            )
        _LOGGER.debug("Initial BLEDevice from cache: %s", ble_device)
    except (AttributeError, ValueError):
        _LOGGER.debug("Could not get BLEDevice from cache", exc_info=True)

    opts = entry.options
    client = MelittaBleClient(
        address,
        device_name=device_name,
        ble_device=ble_device,
        poll_interval=opts.get(CONF_POLL_INTERVAL, DEFAULT_POLL_INTERVAL),
        ble_connect_timeout=opts.get(CONF_BLE_CONNECT_TIMEOUT, DEFAULT_BLE_CONNECT_TIMEOUT),
        frame_timeout=opts.get(CONF_FRAME_TIMEOUT, DEFAULT_FRAME_TIMEOUT),
        max_consecutive_errors=opts.get(CONF_MAX_CONSECUTIVE_ERRORS, DEFAULT_MAX_CONSECUTIVE_ERRORS),
        reconnect_delay=opts.get(CONF_RECONNECT_DELAY, DEFAULT_RECONNECT_DELAY),
        reconnect_max_delay=opts.get(CONF_RECONNECT_MAX_DELAY, DEFAULT_RECONNECT_MAX_DELAY),
        recipe_retries=opts.get(CONF_RECIPE_RETRIES, DEFAULT_RECIPE_RETRIES),
    )

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = client

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    @callback
    def _on_ble_advertisement(
        service_info: bluetooth.BluetoothServiceInfoBleak,
        change: bluetooth.BluetoothChange,
    ) -> None:
        client.set_ble_device(service_info.device)

    entry.async_on_unload(
        bluetooth.async_register_callback(
            hass,
            _on_ble_advertisement,
            {"address": address},
            bluetooth.BluetoothScanningMode.ACTIVE,
        )
    )

    async def _initial_connect() -> None:
        success = await client.connect()
        if success:
            _LOGGER.info("Initial connection to %s succeeded", address)
        else:
            _LOGGER.info("Initial connection to %s failed, will retry on next advertisement", address)
            client._schedule_reconnect()

    entry.async_create_background_task(
        hass, _initial_connect(), f"melitta_barista_connect_{address}"
    )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload Melitta Barista entry."""
    client: MelittaBleClient = hass.data[DOMAIN].get(entry.entry_id)
    if client:
        await client.disconnect()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)

    return unload_ok
