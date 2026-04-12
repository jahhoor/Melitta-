"""D-Bus utilities for BlueZ BLE operations.

Provides low-level D-Bus helpers for pairing and device management.
Used by ble_agent.py (config flow pairing). NOT used during regular
BLE connections (ble_client.py uses Bleak's built-in pair parameter).

IMPORTANT: This module must NOT use 'from __future__ import annotations'
because dbus-fast inspects type annotations at class definition time.
"""

import asyncio
import logging

from dbus_fast import BusType, Variant
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, dbus_method

_LOGGER = logging.getLogger("melitta_barista")

AGENT_PATH = "/melitta/pairing_agent"
BLUEZ_SERVICE = "org.bluez"
ADAPTER_PATH = "/org/bluez/hci0"


def _device_path(address: str) -> str:
    return ADAPTER_PATH + "/dev_" + address.upper().replace(":", "_")


class NoInputOutputAgent(ServiceInterface):
    """BlueZ Agent1 for 'Just Works' BLE pairing (NoInputNoOutput)."""

    def __init__(self) -> None:
        super().__init__("org.bluez.Agent1")

    @dbus_method()
    def Release(self) -> None:
        _LOGGER.debug("Agent1.Release")

    @dbus_method()
    def RequestConfirmation(self, device: "o", passkey: "u") -> None:  # noqa: F821
        _LOGGER.debug("Agent1.RequestConfirmation %s passkey=%s", device, passkey)

    @dbus_method()
    def RequestAuthorization(self, device: "o") -> None:  # noqa: F821
        _LOGGER.debug("Agent1.RequestAuthorization %s", device)

    @dbus_method()
    def AuthorizeService(self, device: "o", uuid: "s") -> None:  # noqa: F821
        _LOGGER.debug("Agent1.AuthorizeService %s uuid=%s", device, uuid)

    @dbus_method()
    def RequestPasskey(self, device: "o") -> "u":  # noqa: F821
        _LOGGER.debug("Agent1.RequestPasskey %s", device)
        return 0

    @dbus_method()
    def RequestPinCode(self, device: "o") -> "s":  # noqa: F821
        _LOGGER.debug("Agent1.RequestPinCode %s", device)
        return "0000"

    @dbus_method()
    def DisplayPasskey(self, device: "o", passkey: "u", entered: "q") -> None:  # noqa: F821
        _LOGGER.debug("Agent1.DisplayPasskey %s passkey=%s", device, passkey)

    @dbus_method()
    def DisplayPinCode(self, device: "o", pincode: "s") -> None:  # noqa: F821
        _LOGGER.debug("Agent1.DisplayPinCode %s pin=%s", device, pincode)

    @dbus_method()
    def Cancel(self) -> None:
        _LOGGER.debug("Agent1.Cancel")


async def connect_bus() -> MessageBus:
    """Connect to the system D-Bus."""
    return await MessageBus(bus_type=BusType.SYSTEM).connect()


def disconnect_bus(bus) -> None:
    """Disconnect from D-Bus, suppressing errors."""
    if bus is not None:
        try:
            bus.disconnect()
        except Exception:  # noqa: BLE001
            pass


async def has_bluez_adapter() -> bool:
    """Check if a local BlueZ adapter (hci0) is available."""
    bus = None
    try:
        bus = await connect_bus()
        introspection = await bus.introspect(BLUEZ_SERVICE, ADAPTER_PATH)
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, ADAPTER_PATH, introspection)
        proxy.get_interface("org.bluez.Adapter1")
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        disconnect_bus(bus)


async def get_adapter(bus):
    """Get BlueZ Adapter1 interface, or None if not available."""
    try:
        introspection = await bus.introspect(BLUEZ_SERVICE, ADAPTER_PATH)
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, ADAPTER_PATH, introspection)
        return proxy.get_interface("org.bluez.Adapter1")
    except Exception:  # noqa: BLE001
        return None


async def register_agent(bus) -> None:
    """Export a NoInputOutputAgent and register it with BlueZ AgentManager1."""
    agent = NoInputOutputAgent()
    bus.export(AGENT_PATH, agent)
    introspection = await bus.introspect(BLUEZ_SERVICE, "/org/bluez")
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, "/org/bluez", introspection)
    agent_mgr = proxy.get_interface("org.bluez.AgentManager1")
    await agent_mgr.call_register_agent(AGENT_PATH, "NoInputNoOutput")
    _LOGGER.debug("Agent registered at %s", AGENT_PATH)
    try:
        await agent_mgr.call_request_default_agent(AGENT_PATH)
    except Exception:  # noqa: BLE001
        _LOGGER.debug("RequestDefaultAgent failed (non-critical)")


async def unregister_agent(bus) -> None:
    """Unregister the pairing agent from BlueZ."""
    try:
        introspection = await bus.introspect(BLUEZ_SERVICE, "/org/bluez")
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, "/org/bluez", introspection)
        agent_mgr = proxy.get_interface("org.bluez.AgentManager1")
        await agent_mgr.call_unregister_agent(AGENT_PATH)
    except Exception:  # noqa: BLE001
        pass


async def check_paired(bus, address: str) -> bool | None:
    """Check if device is already paired. Returns True/False or None if unknown."""
    dev_path = _device_path(address)
    try:
        introspection = await bus.introspect(BLUEZ_SERVICE, dev_path)
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, dev_path, introspection)
        props = proxy.get_interface("org.freedesktop.DBus.Properties")
        paired_var = await props.call_get("org.bluez.Device1", "Paired")
        if paired_var.value:
            _LOGGER.info("Device %s is already paired", address)
            return True
        return False
    except Exception:  # noqa: BLE001
        _LOGGER.debug("Device %s not known to BlueZ", address)
        return None


async def wait_for_device(bus, address: str, timeout: float = 15.0) -> bool:
    """Wait for a BLE device to appear in BlueZ (via advertisements)."""
    dev_path = _device_path(address)
    for _ in range(int(timeout)):
        try:
            await bus.introspect(BLUEZ_SERVICE, dev_path)
            return True
        except Exception:  # noqa: BLE001
            await asyncio.sleep(1)
    return False


async def start_discovery(adapter) -> bool:
    """Start BLE discovery on the adapter."""
    try:
        await adapter.call_start_discovery()
        return True
    except Exception as ex:  # noqa: BLE001
        _LOGGER.debug("StartDiscovery failed: %s", ex)
        return False


async def stop_discovery(adapter) -> None:
    """Stop BLE discovery on the adapter."""
    try:
        await adapter.call_stop_discovery()
    except Exception:  # noqa: BLE001
        pass


async def pair_and_trust(bus, address: str, timeout: float = 30.0) -> str:
    """Perform D-Bus pairing and set device as trusted. Returns result string."""
    dev_path = _device_path(address)
    introspection = await bus.introspect(BLUEZ_SERVICE, dev_path)
    proxy = bus.get_proxy_object(BLUEZ_SERVICE, dev_path, introspection)
    device_iface = proxy.get_interface("org.bluez.Device1")

    try:
        await asyncio.wait_for(device_iface.call_pair(), timeout=timeout)
    except asyncio.TimeoutError:
        _LOGGER.error("Pairing timeout for %s", address)
        return "pairing_timeout"
    except Exception as ex:  # noqa: BLE001
        if "AlreadyExists" in str(ex):
            _LOGGER.info("Device %s already paired", address)
        else:
            _LOGGER.error("Pairing failed for %s: %s", address, ex)
            return "pairing_failed"

    try:
        props = proxy.get_interface("org.freedesktop.DBus.Properties")
        await props.call_set("org.bluez.Device1", "Trusted", Variant("b", True))
        _LOGGER.debug("Device %s set as trusted", address)
    except Exception:  # noqa: BLE001
        _LOGGER.warning("Failed to set Trusted for %s", address)

    _LOGGER.info("Pairing with %s succeeded", address)
    return "ok"
