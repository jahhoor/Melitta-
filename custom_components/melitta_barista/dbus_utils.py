"""D-Bus utilities for BlueZ BLE operations.

Provides low-level D-Bus helpers for pairing, encryption, CCCD writes,
and notification verification. Used by both ble_client.py (connection flow)
and ble_agent.py (config flow pairing).

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


async def _connect_bus() -> MessageBus:
    try:
        return await MessageBus(bus_type=BusType.SYSTEM).connect()
    except EOFError:
        _LOGGER.debug("EOFError on bus connect, retrying with fresh bus")
        await asyncio.sleep(0.3)
        return await MessageBus(bus_type=BusType.SYSTEM).connect()


def _disconnect_bus(bus) -> None:
    if bus is not None:
        try:
            bus.disconnect()
        except Exception:  # noqa: BLE001
            pass


async def _get_device_props(bus, address: str):
    dev_path = _device_path(address)
    try:
        introspection = await bus.introspect(BLUEZ_SERVICE, dev_path)
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, dev_path, introspection)
        return proxy.get_interface("org.freedesktop.DBus.Properties")
    except Exception:  # noqa: BLE001
        return None


async def _get_device_iface(bus, address: str):
    dev_path = _device_path(address)
    try:
        introspection = await bus.introspect(BLUEZ_SERVICE, dev_path)
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, dev_path, introspection)
        return proxy.get_interface("org.bluez.Device1")
    except Exception:  # noqa: BLE001
        return None


async def has_bluez_adapter() -> bool:
    bus = None
    try:
        bus = await _connect_bus()
        introspection = await bus.introspect(BLUEZ_SERVICE, ADAPTER_PATH)
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, ADAPTER_PATH, introspection)
        proxy.get_interface("org.bluez.Adapter1")
        return True
    except Exception:  # noqa: BLE001
        return False
    finally:
        _disconnect_bus(bus)


async def check_paired(address: str) -> bool | None:
    bus = None
    try:
        bus = await _connect_bus()
        props = await _get_device_props(bus, address)
        if props is None:
            _LOGGER.debug("Device %s not known to BlueZ", address)
            return None
        paired_var = await props.call_get("org.bluez.Device1", "Paired")
        result = bool(paired_var.value)
        _LOGGER.debug("D-Bus Paired=%s for %s", result, address)
        return result
    except EOFError:
        _LOGGER.debug("EOFError checking paired status for %s", address)
        return None
    except Exception:  # noqa: BLE001
        _LOGGER.debug("Error checking paired for %s", address, exc_info=True)
        return None
    finally:
        _disconnect_bus(bus)


async def register_agent(bus) -> None:
    agent = NoInputOutputAgent()
    bus.export(AGENT_PATH, agent)
    try:
        introspection = await bus.introspect(BLUEZ_SERVICE, "/org/bluez")
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, "/org/bluez", introspection)
        agent_mgr = proxy.get_interface("org.bluez.AgentManager1")
        await agent_mgr.call_register_agent(AGENT_PATH, "NoInputNoOutput")
        _LOGGER.debug("Agent registered at %s", AGENT_PATH)
        try:
            await agent_mgr.call_request_default_agent(AGENT_PATH)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("RequestDefaultAgent failed (non-critical)")
    except Exception:  # noqa: BLE001
        _LOGGER.debug("Agent registration failed", exc_info=True)


async def unregister_agent(bus) -> None:
    try:
        introspection = await bus.introspect(BLUEZ_SERVICE, "/org/bluez")
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, "/org/bluez", introspection)
        agent_mgr = proxy.get_interface("org.bluez.AgentManager1")
        await agent_mgr.call_unregister_agent(AGENT_PATH)
    except Exception:  # noqa: BLE001
        pass


async def pair_device(address: str, timeout: float = 30.0) -> str:
    bus = None
    try:
        bus = await _connect_bus()
        await register_agent(bus)

        dev_iface = await _get_device_iface(bus, address)
        if dev_iface is None:
            _LOGGER.debug("Device %s not found for D-Bus pairing", address)
            return "not_found"

        try:
            await asyncio.wait_for(dev_iface.call_pair(), timeout=timeout)
        except asyncio.TimeoutError:
            _LOGGER.warning("D-Bus pairing timeout for %s", address)
            return "pairing_timeout"
        except Exception as ex:  # noqa: BLE001
            if "AlreadyExists" in str(ex):
                _LOGGER.debug("Device %s already paired (AlreadyExists)", address)
            else:
                _LOGGER.warning("D-Bus pairing failed for %s: %s", address, ex)
                return "pairing_failed"

        props = await _get_device_props(bus, address)
        if props is not None:
            try:
                await props.call_set(
                    "org.bluez.Device1", "Trusted", Variant("b", True)
                )
                _LOGGER.debug("Device %s set as trusted", address)
            except Exception:  # noqa: BLE001
                _LOGGER.debug("Failed to set Trusted for %s", address)

        _LOGGER.info("D-Bus pairing with %s succeeded", address)
        return "ok"
    except EOFError:
        _LOGGER.debug("EOFError during D-Bus pairing for %s", address)
        return "pairing_failed"
    except Exception:  # noqa: BLE001
        _LOGGER.debug("D-Bus pairing error for %s", address, exc_info=True)
        return "pairing_failed"
    finally:
        if bus:
            await unregister_agent(bus)
            _disconnect_bus(bus)


async def unpair_device(address: str) -> bool:
    bus = None
    try:
        bus = await _connect_bus()
        try:
            introspection = await bus.introspect(BLUEZ_SERVICE, ADAPTER_PATH)
            proxy = bus.get_proxy_object(BLUEZ_SERVICE, ADAPTER_PATH, introspection)
            adapter = proxy.get_interface("org.bluez.Adapter1")
            dev_path = _device_path(address)
            await adapter.call_remove_device(dev_path)
            _LOGGER.info("D-Bus unpaired (removed) %s", address)
            return True
        except Exception as ex:  # noqa: BLE001
            if "DoesNotExist" in str(ex):
                _LOGGER.debug("Device %s not found for removal", address)
                return True
            _LOGGER.debug("D-Bus unpair failed for %s: %s", address, ex)
            return False
    except EOFError:
        _LOGGER.debug("EOFError during D-Bus unpair for %s", address)
        return False
    except Exception:  # noqa: BLE001
        _LOGGER.debug("D-Bus unpair error for %s", address, exc_info=True)
        return False
    finally:
        _disconnect_bus(bus)


async def force_encryption(address: str, timeout: float = 10.0) -> bool:
    bus = None
    try:
        bus = await _connect_bus()
        await register_agent(bus)

        dev_iface = await _get_device_iface(bus, address)
        if dev_iface is None:
            _LOGGER.debug("Device %s not found for force_encryption", address)
            return False

        try:
            await asyncio.wait_for(dev_iface.call_pair(), timeout=timeout)
            _LOGGER.debug("force_encryption: Pair() succeeded for %s", address)
        except asyncio.TimeoutError:
            _LOGGER.debug("force_encryption: Pair() timeout for %s", address)
            return False
        except Exception as ex:  # noqa: BLE001
            if "AlreadyExists" in str(ex):
                _LOGGER.debug(
                    "force_encryption: AlreadyExists for %s (expected)", address
                )
            else:
                _LOGGER.debug("force_encryption: Pair() error for %s: %s", address, ex)
                return False

        return True
    except EOFError:
        _LOGGER.debug("EOFError during force_encryption for %s", address)
        return False
    except Exception:  # noqa: BLE001
        _LOGGER.debug("force_encryption error for %s", address, exc_info=True)
        return False
    finally:
        if bus:
            await unregister_agent(bus)
            _disconnect_bus(bus)


async def write_cccd(address: str, char_uuid: str, enable: bool = True) -> bool:
    cccd_value = bytes([0x01, 0x00]) if enable else bytes([0x00, 0x00])
    bus = None
    try:
        bus = await _connect_bus()
        dev_path = _device_path(address)

        try:
            dev_intro = await bus.introspect(BLUEZ_SERVICE, dev_path)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("Device %s not found for CCCD write", address)
            return False

        char_path = None
        uuid_lower = char_uuid.lower()
        for node in dev_intro.nodes:
            service_path = f"{dev_path}/{node.name}"
            try:
                svc_intro = await bus.introspect(BLUEZ_SERVICE, service_path)
            except Exception:  # noqa: BLE001
                continue
            for char_node in svc_intro.nodes:
                full_char_path = f"{service_path}/{char_node.name}"
                try:
                    char_intro = await bus.introspect(BLUEZ_SERVICE, full_char_path)
                    char_proxy = bus.get_proxy_object(
                        BLUEZ_SERVICE, full_char_path, char_intro
                    )
                    char_props = char_proxy.get_interface(
                        "org.freedesktop.DBus.Properties"
                    )
                    uuid_var = await char_props.call_get(
                        "org.bluez.GattCharacteristic1", "UUID"
                    )
                    if uuid_var.value.lower() == uuid_lower:
                        char_path = full_char_path
                        break
                except Exception:  # noqa: BLE001
                    continue
            if char_path:
                break

        if char_path is None:
            _LOGGER.debug("CCCD: characteristic %s not found on %s", char_uuid, address)
            return False

        try:
            char_intro = await bus.introspect(BLUEZ_SERVICE, char_path)
            char_proxy = bus.get_proxy_object(BLUEZ_SERVICE, char_path, char_intro)
            gatt_char = char_proxy.get_interface("org.bluez.GattCharacteristic1")
            await gatt_char.call_start_notify()
            _LOGGER.debug("D-Bus StartNotify succeeded for %s", char_uuid)
        except EOFError:
            _LOGGER.debug("EOFError during StartNotify, reconnecting bus and retrying")
            _disconnect_bus(bus)
            try:
                bus = await _connect_bus()
                char_intro = await bus.introspect(BLUEZ_SERVICE, char_path)
                char_proxy = bus.get_proxy_object(
                    BLUEZ_SERVICE, char_path, char_intro
                )
                gatt_char = char_proxy.get_interface(
                    "org.bluez.GattCharacteristic1"
                )
                await gatt_char.call_start_notify()
                _LOGGER.debug("D-Bus StartNotify succeeded after bus reconnect")
            except Exception:  # noqa: BLE001
                _LOGGER.debug("D-Bus StartNotify retry after EOFError also failed", exc_info=True)
        except Exception as ex:  # noqa: BLE001
            if "Already notifying" in str(ex) or "NotPermitted" in str(ex):
                _LOGGER.debug("D-Bus StartNotify: %s (non-critical)", ex)
            else:
                _LOGGER.debug("D-Bus StartNotify failed: %s", ex)

        for desc_node in char_intro.nodes if char_intro else []:
            desc_path = f"{char_path}/{desc_node.name}"
            try:
                desc_intro = await bus.introspect(BLUEZ_SERVICE, desc_path)
                desc_proxy = bus.get_proxy_object(
                    BLUEZ_SERVICE, desc_path, desc_intro
                )
                desc_props = desc_proxy.get_interface(
                    "org.freedesktop.DBus.Properties"
                )
                uuid_var = await desc_props.call_get(
                    "org.bluez.GattDescriptor1", "UUID"
                )
                if uuid_var.value.lower() == "00002902-0000-1000-8000-00805f9b34fb":
                    desc_iface = desc_proxy.get_interface(
                        "org.bluez.GattDescriptor1"
                    )
                    await desc_iface.call_write_value(cccd_value, {})
                    _LOGGER.debug(
                        "CCCD write succeeded for %s: %s",
                        char_uuid, cccd_value.hex(),
                    )
                    return True
            except EOFError:
                _LOGGER.debug("EOFError during CCCD descriptor write, reconnecting bus")
                _disconnect_bus(bus)
                try:
                    bus = await _connect_bus()
                    desc_intro = await bus.introspect(BLUEZ_SERVICE, desc_path)
                    desc_proxy = bus.get_proxy_object(
                        BLUEZ_SERVICE, desc_path, desc_intro
                    )
                    desc_iface = desc_proxy.get_interface(
                        "org.bluez.GattDescriptor1"
                    )
                    await desc_iface.call_write_value(cccd_value, {})
                    _LOGGER.debug("CCCD write succeeded after bus reconnect")
                    return True
                except Exception:  # noqa: BLE001
                    _LOGGER.debug("CCCD write retry after EOFError failed", exc_info=True)
            except Exception:  # noqa: BLE001
                _LOGGER.debug("CCCD descriptor write error", exc_info=True)

        _LOGGER.debug("CCCD descriptor not found for %s, StartNotify may suffice", char_uuid)
        return True

    except EOFError:
        _LOGGER.debug("EOFError during CCCD write for %s", address)
        return False
    except Exception:  # noqa: BLE001
        _LOGGER.debug("CCCD write error for %s", address, exc_info=True)
        return False
    finally:
        _disconnect_bus(bus)


async def check_notifying(address: str, char_uuid: str) -> bool:
    bus = None
    try:
        bus = await _connect_bus()
        dev_path = _device_path(address)

        uuid_lower = char_uuid.lower()
        try:
            dev_intro = await bus.introspect(BLUEZ_SERVICE, dev_path)
        except Exception:  # noqa: BLE001
            return False

        for node in dev_intro.nodes:
            service_path = f"{dev_path}/{node.name}"
            try:
                svc_intro = await bus.introspect(BLUEZ_SERVICE, service_path)
            except Exception:  # noqa: BLE001
                continue
            for char_node in svc_intro.nodes:
                full_char_path = f"{service_path}/{char_node.name}"
                try:
                    char_intro = await bus.introspect(BLUEZ_SERVICE, full_char_path)
                    char_proxy = bus.get_proxy_object(
                        BLUEZ_SERVICE, full_char_path, char_intro
                    )
                    char_props = char_proxy.get_interface(
                        "org.freedesktop.DBus.Properties"
                    )
                    uuid_var = await char_props.call_get(
                        "org.bluez.GattCharacteristic1", "UUID"
                    )
                    if uuid_var.value.lower() != uuid_lower:
                        continue
                    notifying_var = await char_props.call_get(
                        "org.bluez.GattCharacteristic1", "Notifying"
                    )
                    result = bool(notifying_var.value)
                    _LOGGER.debug("Notifying=%s for %s", result, char_uuid)
                    return result
                except Exception:  # noqa: BLE001
                    continue

        _LOGGER.debug("Could not find Notifying property for %s", char_uuid)
        return False
    except EOFError:
        _LOGGER.debug("EOFError checking Notifying for %s", address)
        return False
    except Exception:  # noqa: BLE001
        _LOGGER.debug("Error checking Notifying for %s", address, exc_info=True)
        return False
    finally:
        _disconnect_bus(bus)


async def wait_for_device(address: str, timeout: float = 15.0) -> bool:
    bus = None
    dev_path = _device_path(address)
    discovery_started = False
    try:
        bus = await _connect_bus()

        try:
            introspection = await bus.introspect(BLUEZ_SERVICE, ADAPTER_PATH)
            proxy = bus.get_proxy_object(BLUEZ_SERVICE, ADAPTER_PATH, introspection)
            adapter = proxy.get_interface("org.bluez.Adapter1")
            await adapter.call_start_discovery()
            discovery_started = True
            _LOGGER.debug("Discovery started, waiting for %s", address)
        except Exception:  # noqa: BLE001
            _LOGGER.debug("StartDiscovery failed (non-critical)")

        for _ in range(int(timeout)):
            try:
                await bus.introspect(BLUEZ_SERVICE, dev_path)
                return True
            except Exception:  # noqa: BLE001
                await asyncio.sleep(1)

        _LOGGER.debug("Device %s not found after %.0fs discovery", address, timeout)
        return False
    except Exception:  # noqa: BLE001
        return False
    finally:
        if discovery_started and bus:
            try:
                introspection = await bus.introspect(BLUEZ_SERVICE, ADAPTER_PATH)
                proxy = bus.get_proxy_object(
                    BLUEZ_SERVICE, ADAPTER_PATH, introspection
                )
                adapter = proxy.get_interface("org.bluez.Adapter1")
                await adapter.call_stop_discovery()
            except Exception:  # noqa: BLE001
                pass
        _disconnect_bus(bus)
