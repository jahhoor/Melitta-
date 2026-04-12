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

    When no local BlueZ adapter is available (e.g. using ESPHome BLE proxy),
    pairing is skipped — the proxy handles BLE bonding at the ESP32 level.

    Returns: "ok", "pairing_failed", "pairing_timeout", or "cannot_connect".
    """
    bus = None
    discovery_started = False
    adapter = None

    try:
        bus = await dbus_utils.connect_bus()

        adapter = await dbus_utils.get_adapter(bus)
        if adapter is None:
            _LOGGER.info(
                "No functional BlueZ adapter (hci0) found. "
                "Assuming ESPHome BLE proxy — skipping D-Bus pairing for %s",
                address,
            )
            return "ok"

        await dbus_utils.register_agent(bus)

        paired = await dbus_utils.check_paired(bus, address)
        if paired is True:
            return "ok"

        if paired is None:
            _LOGGER.debug("Device %s not known to BlueZ, starting discovery", address)
            discovery_started = await dbus_utils.start_discovery(adapter)

            if not await dbus_utils.wait_for_device(bus, address, timeout=15.0):
                _LOGGER.error(
                    "Device %s not found after discovery. "
                    "Make sure it is powered on and in range.",
                    address,
                )
                return "cannot_connect"

        _LOGGER.info("Initiating D-Bus pairing with %s", address)
        return await dbus_utils.pair_and_trust(bus, address, timeout=timeout)

    except Exception:  # noqa: BLE001
        _LOGGER.exception("D-Bus pairing error for %s", address)
        return "pairing_failed"
    finally:
        if bus:
            if discovery_started and adapter:
                await dbus_utils.stop_discovery(adapter)
            await dbus_utils.unregister_agent(bus)
            dbus_utils.disconnect_bus(bus)
