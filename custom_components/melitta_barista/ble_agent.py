"""BlueZ D-Bus Agent1 for BLE pairing (config flow entry point).

This module provides async_pair_device() for use by config_flow.py during
device setup. Uses shared D-Bus utilities from dbus_utils.py.

IMPORTANT: This module must NOT use 'from __future__ import annotations'
because dbus-fast inspects type annotations at class definition time.
"""

import logging

from . import dbus_utils

_LOGGER = logging.getLogger("melitta_barista")


async def async_pair_device(address: str, timeout: float = 30.0) -> str:
    """Pair a BLE device via D-Bus BlueZ API with a registered Agent1.

    Returns: "ok", "pairing_failed", "pairing_timeout", or "cannot_connect".
    """
    has_adapter = await dbus_utils.has_bluez_adapter()
    if not has_adapter:
        _LOGGER.info(
            "No functional BlueZ adapter found. "
            "Assuming ESPHome BLE proxy — skipping D-Bus pairing for %s",
            address,
        )
        return "ok"

    paired = await dbus_utils.check_paired(address)
    if paired is True:
        _LOGGER.info("Device %s is already paired", address)
        return "ok"

    if paired is None:
        device_found = await dbus_utils.wait_for_device(address, timeout=15.0)
        if not device_found:
            _LOGGER.info(
                "Device %s not found after discovery. "
                "Make sure it is powered on and in range.",
                address,
            )
            return "cannot_connect"

    _LOGGER.info("Initiating D-Bus pairing with %s", address)
    result = await dbus_utils.pair_device(address, timeout=timeout)

    if result == "ok":
        return "ok"
    elif result == "pairing_timeout":
        return "pairing_timeout"
    else:
        return "pairing_failed"
