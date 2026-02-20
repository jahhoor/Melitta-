import asyncio
import logging
import re
from typing import Any

_LOGGER = logging.getLogger(__name__)

AGENT_PATH = "/org/melitta/agent"
AGENT_CAPABILITY = "NoInputNoOutput"


async def _get_bus():
    from dbus_fast.aio import MessageBus
    from dbus_fast import BusType
    return await MessageBus(bus_type=BusType.SYSTEM).connect()


async def _get_adapters(bus) -> list[str]:
    from dbus_fast import Message, MessageType
    reply = await bus.call(Message(
        destination="org.bluez", path="/org/bluez",
        interface="org.freedesktop.DBus.Introspectable",
        member="Introspect",
    ))
    adapters = re.findall(r'<node name="(hci\d+)"', reply.body[0]) if reply.body else []
    return adapters or ["hci0"]


def _device_path(adapter: str, address: str) -> str:
    mac_path = address.replace(":", "_").upper()
    return f"/org/bluez/{adapter}/dev_{mac_path}"


async def _get_device_property(bus, device_path: str, prop: str) -> Any:
    from dbus_fast import Message, MessageType, Variant
    reply = await asyncio.wait_for(
        bus.call(Message(
            destination="org.bluez", path=device_path,
            interface="org.freedesktop.DBus.Properties",
            member="Get", signature="ss",
            body=["org.bluez.Device1", prop],
        )),
        timeout=2.0,
    )
    if reply.message_type == MessageType.ERROR:
        return None
    val = reply.body[0] if reply.body else None
    if hasattr(val, 'value'):
        val = val.value
    return val


async def dbus_check_paired(address: str) -> bool:
    try:
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                val = await _get_device_property(bus, dp, "Paired")
                if val is not None and bool(val):
                    return True
            return False
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("dbus_check_paired error: %s", err)
        return False


async def dbus_pair_device(address: str, status_callback=None) -> bool:
    try:
        from dbus_fast import Message, MessageType, Variant
        from dbus_fast.service import ServiceInterface, method as dbus_method

        class PairingAgent(ServiceInterface):
            def __init__(self):
                super().__init__("org.bluez.Agent1")

            @dbus_method()
            def Release(self) -> "":
                pass

            @dbus_method()
            def RequestPinCode(self, device: "o") -> "s":
                _LOGGER.info("BLE agent: RequestPinCode -> '0000'")
                return "0000"

            @dbus_method()
            def DisplayPinCode(self, device: "o", pincode: "s") -> "":
                pass

            @dbus_method()
            def RequestPasskey(self, device: "o") -> "u":
                _LOGGER.info("BLE agent: RequestPasskey -> 0")
                return 0

            @dbus_method()
            def DisplayPasskey(self, device: "o", passkey: "u", entered: "q") -> "":
                pass

            @dbus_method()
            def RequestConfirmation(self, device: "o", passkey: "u") -> "":
                _LOGGER.info("BLE agent: auto-accepting confirmation")

            @dbus_method()
            def RequestAuthorization(self, device: "o") -> "":
                _LOGGER.info("BLE agent: auto-accepting authorization")

            @dbus_method()
            def AuthorizeService(self, device: "o", uuid: "s") -> "":
                pass

            @dbus_method()
            def Cancel(self) -> "":
                pass

        bus = await _get_bus()
        agent = PairingAgent()
        agent_registered = False
        try:
            try:
                await bus.request_name("org.melitta.agent")
            except Exception:
                pass

            bus.export(AGENT_PATH, agent)

            reg_reply = await bus.call(Message(
                destination="org.bluez", path="/org/bluez",
                interface="org.bluez.AgentManager1",
                member="RegisterAgent",
                signature="os",
                body=[AGENT_PATH, AGENT_CAPABILITY],
            ))
            if reg_reply.message_type == MessageType.ERROR:
                if "AlreadyExists" not in (reg_reply.error_name or ""):
                    _LOGGER.warning("BLE agent registration failed: %s", reg_reply.error_name)
                    return False
            agent_registered = True

            await bus.call(Message(
                destination="org.bluez", path="/org/bluez",
                interface="org.bluez.AgentManager1",
                member="RequestDefaultAgent",
                signature="o",
                body=[AGENT_PATH],
            ))

            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                paired = await _get_device_property(bus, dp, "Paired")
                if paired is None:
                    continue
                if bool(paired):
                    _LOGGER.info("Device %s already paired on %s", address, adapter)
                    return True

                if status_callback:
                    status_callback(
                        "pairing",
                        "Bluetooth-koppeling bezig... Zorg dat de machine in 'Verbinden' modus staat.",
                    )

                _LOGGER.info("Pairing %s on %s - machine must be in Verbinden mode", address, adapter)
                pair_reply = await asyncio.wait_for(
                    bus.call(Message(
                        destination="org.bluez", path=dp,
                        interface="org.bluez.Device1",
                        member="Pair",
                    )),
                    timeout=30.0,
                )

                if pair_reply.message_type == MessageType.ERROR:
                    if "AlreadyExists" in (pair_reply.error_name or ""):
                        return True
                    _LOGGER.warning("Pair() failed: %s", pair_reply.error_name)
                    return False

                _LOGGER.info("Pair() succeeded for %s", address)
                await asyncio.sleep(0.5)

                await bus.call(Message(
                    destination="org.bluez", path=dp,
                    interface="org.freedesktop.DBus.Properties",
                    member="Set", signature="ssv",
                    body=["org.bluez.Device1", "Trusted", Variant("b", True)],
                ))
                return True

            _LOGGER.warning("No adapter found with device %s", address)
            return False
        finally:
            if agent_registered:
                try:
                    await bus.call(Message(
                        destination="org.bluez", path="/org/bluez",
                        interface="org.bluez.AgentManager1",
                        member="UnregisterAgent",
                        signature="o",
                        body=[AGENT_PATH],
                    ))
                except Exception:
                    pass
            try:
                bus.unexport(AGENT_PATH, agent)
            except Exception:
                pass
            try:
                bus.disconnect()
            except Exception:
                pass
    except asyncio.TimeoutError:
        _LOGGER.warning("Pair() timed out (30s) for %s", address)
        return False
    except ImportError:
        _LOGGER.warning("dbus_fast not available for pairing")
        return False
    except Exception as err:
        _LOGGER.warning("Pair error: %s (%s)", err, type(err).__name__)
        return False


async def dbus_check_bond_valid(address: str) -> bool:
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                paired = await _get_device_property(bus, dp, "Paired")
                if not paired:
                    continue
                connected = await _get_device_property(bus, dp, "Connected")
                if not connected:
                    _LOGGER.debug("Bond check: device not connected, assuming valid (will verify on connect)")
                    return True
                for wait in range(6):
                    services_resolved = await _get_device_property(bus, dp, "ServicesResolved")
                    if services_resolved:
                        _LOGGER.debug("Bond check: ServicesResolved=True after %ds, bond is valid", wait)
                        return True
                    await asyncio.sleep(0.5)
                _LOGGER.info("Bond check: ServicesResolved still False after 3s - stale bond detected")
                return False
            return True
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("Bond check error: %s", err)
        return True


async def dbus_force_encryption(address: str) -> bool:
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                reply = await asyncio.wait_for(
                    bus.call(Message(
                        destination="org.bluez", path=dp,
                        interface="org.bluez.Device1",
                        member="Pair",
                    )),
                    timeout=5.0,
                )
                if reply.message_type == MessageType.ERROR:
                    if "AlreadyExists" in (reply.error_name or ""):
                        _LOGGER.debug("Encryption already active (AlreadyExists)")
                        return True
                    _LOGGER.debug("Force encryption Pair() error: %s", reply.error_name)
                    return False
                return True
            return False
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("Force encryption error: %s", err)
        return False


async def dbus_cancel_pairing(address: str):
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                await bus.call(Message(
                    destination="org.bluez", path=dp,
                    interface="org.bluez.Device1",
                    member="CancelPairing",
                ))
                _LOGGER.debug("CancelPairing sent for %s", address)
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("CancelPairing error (expected if not pairing): %s", err)


async def dbus_force_disconnect(address: str):
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                connected = await _get_device_property(bus, dp, "Connected")
                if connected:
                    await bus.call(Message(
                        destination="org.bluez", path=dp,
                        interface="org.bluez.Device1",
                        member="Disconnect",
                    ))
                    _LOGGER.debug("BlueZ force disconnect sent for %s", address)
                    await asyncio.sleep(1.0)
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("Force disconnect error: %s", err)


async def dbus_remove_device(address: str) -> bool:
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            mac_path = address.replace(":", "_").upper()
            for adapter in await _get_adapters(bus):
                dp = f"/org/bluez/{adapter}/dev_{mac_path}"
                reply = await bus.call(Message(
                    destination="org.bluez",
                    path=f"/org/bluez/{adapter}",
                    interface="org.bluez.Adapter1",
                    member="RemoveDevice",
                    signature="o",
                    body=[dp],
                ))
                if reply.message_type != MessageType.ERROR:
                    _LOGGER.info("RemoveDevice succeeded for %s", address)
                    return True
            return False
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("RemoveDevice error: %s", err)
        return False


async def dbus_write_cccd(char_path: str) -> bool:
    try:
        from dbus_fast import Message, MessageType, Variant
        bus = await _get_bus()
        try:
            introspect = await bus.call(Message(
                destination="org.bluez", path=char_path,
                interface="org.freedesktop.DBus.Introspectable",
                member="Introspect",
            ))
            if introspect.message_type == MessageType.ERROR:
                _LOGGER.debug("CCCD introspect failed for %s", char_path)
                return False

            descriptors = re.findall(r'<node name="(desc\w+)"', introspect.body[0]) if introspect.body else []

            for desc_name in descriptors:
                desc_path = f"{char_path}/{desc_name}"
                uuid_reply = await bus.call(Message(
                    destination="org.bluez", path=desc_path,
                    interface="org.freedesktop.DBus.Properties",
                    member="Get", signature="ss",
                    body=["org.bluez.GattDescriptor1", "UUID"],
                ))
                if uuid_reply.message_type == MessageType.ERROR:
                    continue
                desc_uuid = str(uuid_reply.body[0].value if uuid_reply.body else "")
                if desc_uuid.lower() == "00002902-0000-1000-8000-00805f9b34fb":
                    cccd_value = bytes([0x01, 0x00])
                    write_reply = await asyncio.wait_for(
                        bus.call(Message(
                            destination="org.bluez", path=desc_path,
                            interface="org.bluez.GattDescriptor1",
                            member="WriteValue",
                            signature="aya{sv}",
                            body=[list(cccd_value), {}],
                        )),
                        timeout=3.0,
                    )
                    if write_reply.message_type == MessageType.ERROR:
                        _LOGGER.debug("CCCD write error: %s", write_reply.error_name)
                        return False
                    _LOGGER.debug("CCCD descriptor written (0x0100) on %s", desc_path)
                    return True

            _LOGGER.debug("No CCCD descriptor (0x2902) found on %s", char_path)
            return False
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("CCCD write error: %s", err)
        return False


async def dbus_check_notifying(char_path: str) -> bool:
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            reply = await asyncio.wait_for(
                bus.call(Message(
                    destination="org.bluez", path=char_path,
                    interface="org.freedesktop.DBus.Properties",
                    member="Get", signature="ss",
                    body=["org.bluez.GattCharacteristic1", "Notifying"],
                )),
                timeout=2.0,
            )
            if reply.message_type == MessageType.ERROR:
                return False
            val = reply.body[0] if reply.body else None
            if hasattr(val, 'value'):
                val = val.value
            return bool(val)
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("Check notifying error: %s", err)
        return False


async def dbus_start_notify(char_path: str) -> bool:
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            reply = await asyncio.wait_for(
                bus.call(Message(
                    destination="org.bluez", path=char_path,
                    interface="org.bluez.GattCharacteristic1",
                    member="StartNotify",
                )),
                timeout=3.0,
            )
            if reply.message_type == MessageType.ERROR:
                _LOGGER.debug("D-Bus StartNotify error: %s", reply.error_name)
                return False
            return True
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("D-Bus StartNotify error: %s", err)
        return False


async def dbus_register_notification_handler(char_path: str, data_callback):
    from dbus_fast import Message, BusType
    from dbus_fast.aio import MessageBus

    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()

    match_rule = (
        f"type='signal',"
        f"sender='org.bluez',"
        f"interface='org.freedesktop.DBus.Properties',"
        f"member='PropertiesChanged',"
        f"path='{char_path}'"
    )
    await bus.call(Message(
        destination="org.freedesktop.DBus",
        path="/org/freedesktop/DBus",
        interface="org.freedesktop.DBus",
        member="AddMatch",
        signature="s",
        body=[match_rule],
    ))

    def on_message(msg):
        if msg.member != "PropertiesChanged":
            return
        msg_path = msg.path if hasattr(msg, 'path') else ""
        if msg_path != char_path:
            return
        if not msg.body or len(msg.body) < 2:
            return
        if msg.body[0] != "org.bluez.GattCharacteristic1":
            return
        changed = msg.body[1]
        if "Value" not in changed:
            return
        value = changed["Value"]
        if hasattr(value, 'value'):
            value = value.value
        try:
            data = bytes(value)
        except Exception:
            return
        if len(data) > 0:
            data_callback(data)

    bus.add_message_handler(on_message)
    return bus, on_message, match_rule


async def dbus_cleanup_notification_handler(bus, handler, match_rule):
    if bus is None:
        return
    try:
        if handler:
            bus.remove_message_handler(handler)
        if match_rule:
            from dbus_fast import Message
            try:
                await bus.call(Message(
                    destination="org.freedesktop.DBus",
                    path="/org/freedesktop/DBus",
                    interface="org.freedesktop.DBus",
                    member="RemoveMatch",
                    signature="s",
                    body=[match_rule],
                ))
            except Exception:
                pass
        bus.disconnect()
    except Exception:
        pass


def get_char_path_from_services(client, uuid: str) -> str | None:
    if not client:
        return None
    try:
        for service in client.services:
            for char in service.characteristics:
                if char.uuid.lower() == uuid.lower():
                    if hasattr(char, 'path'):
                        return char.path
                    if hasattr(char, 'obj') and hasattr(char.obj, 'get_object_path'):
                        return char.obj.get_object_path()
    except Exception:
        pass
    return None


async def get_char_path_via_dbus(address: str, uuid: str) -> str | None:
    try:
        from dbus_fast import Message, MessageType
        uuid_short = uuid.replace("-", "").lower()
        mac_path = address.replace(":", "_").upper()
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                dev_reply = await bus.call(Message(
                    destination="org.bluez", path=dp,
                    interface="org.freedesktop.DBus.Introspectable",
                    member="Introspect",
                ))
                if dev_reply.message_type == MessageType.ERROR:
                    continue
                services = re.findall(r'<node name="(service\w+)"', dev_reply.body[0]) if dev_reply.body else []
                for svc in services:
                    svc_path = f"{dp}/{svc}"
                    svc_reply = await bus.call(Message(
                        destination="org.bluez", path=svc_path,
                        interface="org.freedesktop.DBus.Introspectable",
                        member="Introspect",
                    ))
                    if svc_reply.message_type == MessageType.ERROR:
                        continue
                    chars = re.findall(r'<node name="(char\w+)"', svc_reply.body[0]) if svc_reply.body else []
                    for ch in chars:
                        cp = f"{svc_path}/{ch}"
                        uuid_reply = await bus.call(Message(
                            destination="org.bluez", path=cp,
                            interface="org.freedesktop.DBus.Properties",
                            member="Get", signature="ss",
                            body=["org.bluez.GattCharacteristic1", "UUID"],
                        ))
                        if uuid_reply.message_type == MessageType.ERROR:
                            continue
                        char_uuid = str(uuid_reply.body[0].value if uuid_reply.body else "")
                        if char_uuid.replace("-", "").lower() == uuid_short:
                            return cp
            return None
        finally:
            bus.disconnect()
    except Exception:
        return None
