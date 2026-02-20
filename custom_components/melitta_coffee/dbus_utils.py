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
            adapters = await _get_adapters(bus)
            _LOGGER.debug("DBUS CHECK PAIRED: checking %s on adapters %s", address, adapters)
            for adapter in adapters:
                dp = _device_path(adapter, address)
                val = await _get_device_property(bus, dp, "Paired")
                connected = await _get_device_property(bus, dp, "Connected")
                trusted = await _get_device_property(bus, dp, "Trusted")
                _LOGGER.debug(
                    "DBUS CHECK PAIRED: %s on %s: Paired=%s, Connected=%s, Trusted=%s",
                    address, adapter, val, connected, trusted,
                )
                if val is not None and bool(val):
                    return True
            _LOGGER.debug("DBUS CHECK PAIRED: %s not paired on any adapter", address)
            return False
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS CHECK PAIRED: error for %s: %s (%s)", address, err, type(err).__name__)
        return False


async def dbus_pair_device(address: str, status_callback=None) -> bool:
    _LOGGER.info("DBUS PAIR: starting pairing for %s", address)
    try:
        from dbus_fast import Message, MessageType, Variant
        from dbus_fast.service import ServiceInterface, method as dbus_method

        class PairingAgent(ServiceInterface):
            def __init__(self):
                super().__init__("org.bluez.Agent1")

            @dbus_method()
            def Release(self) -> "":
                _LOGGER.debug("DBUS AGENT: Release called")

            @dbus_method()
            def RequestPinCode(self, device: "o") -> "s":
                _LOGGER.info("DBUS AGENT: RequestPinCode for %s -> '0000'", device)
                return "0000"

            @dbus_method()
            def DisplayPinCode(self, device: "o", pincode: "s") -> "":
                _LOGGER.debug("DBUS AGENT: DisplayPinCode for %s: %s", device, pincode)

            @dbus_method()
            def RequestPasskey(self, device: "o") -> "u":
                _LOGGER.info("DBUS AGENT: RequestPasskey for %s -> 0", device)
                return 0

            @dbus_method()
            def DisplayPasskey(self, device: "o", passkey: "u", entered: "q") -> "":
                _LOGGER.debug("DBUS AGENT: DisplayPasskey for %s: passkey=%d, entered=%d", device, passkey, entered)

            @dbus_method()
            def RequestConfirmation(self, device: "o", passkey: "u") -> "":
                _LOGGER.info("DBUS AGENT: RequestConfirmation for %s, passkey=%d -> auto-accepting", device, passkey)

            @dbus_method()
            def RequestAuthorization(self, device: "o") -> "":
                _LOGGER.info("DBUS AGENT: RequestAuthorization for %s -> auto-accepting", device)

            @dbus_method()
            def AuthorizeService(self, device: "o", uuid: "s") -> "":
                _LOGGER.debug("DBUS AGENT: AuthorizeService for %s, uuid=%s", device, uuid)

            @dbus_method()
            def Cancel(self) -> "":
                _LOGGER.info("DBUS AGENT: Cancel called (pairing cancelled by BlueZ)")

        bus = await _get_bus()
        agent = PairingAgent()
        agent_registered = False
        try:
            try:
                await bus.request_name("org.melitta.agent")
                _LOGGER.debug("DBUS PAIR: claimed bus name org.melitta.agent")
            except Exception as err:
                _LOGGER.debug("DBUS PAIR: bus name claim failed (expected if already held): %s", err)

            bus.export(AGENT_PATH, agent)
            _LOGGER.debug("DBUS PAIR: agent exported on %s", AGENT_PATH)

            reg_reply = await bus.call(Message(
                destination="org.bluez", path="/org/bluez",
                interface="org.bluez.AgentManager1",
                member="RegisterAgent",
                signature="os",
                body=[AGENT_PATH, AGENT_CAPABILITY],
            ))
            if reg_reply.message_type == MessageType.ERROR:
                if "AlreadyExists" not in (reg_reply.error_name or ""):
                    _LOGGER.warning("DBUS PAIR: agent registration failed: %s", reg_reply.error_name)
                    return False
                _LOGGER.debug("DBUS PAIR: agent already registered (AlreadyExists)")
            else:
                _LOGGER.debug("DBUS PAIR: agent registered successfully")
            agent_registered = True

            await bus.call(Message(
                destination="org.bluez", path="/org/bluez",
                interface="org.bluez.AgentManager1",
                member="RequestDefaultAgent",
                signature="o",
                body=[AGENT_PATH],
            ))
            _LOGGER.debug("DBUS PAIR: set as default agent")

            adapters = await _get_adapters(bus)
            _LOGGER.debug("DBUS PAIR: scanning adapters %s for device %s", adapters, address)
            for adapter in adapters:
                dp = _device_path(adapter, address)
                paired = await _get_device_property(bus, dp, "Paired")
                _LOGGER.debug("DBUS PAIR: %s on %s: Paired=%s", address, adapter, paired)
                if paired is None:
                    _LOGGER.debug("DBUS PAIR: device not found on adapter %s, skipping", adapter)
                    continue
                if bool(paired):
                    _LOGGER.info("DBUS PAIR: device %s already paired on %s", address, adapter)
                    return True

                if status_callback:
                    status_callback(
                        "pairing",
                        "Bluetooth-koppeling bezig... Zorg dat de machine in 'Verbinden' modus staat.",
                    )

                _LOGGER.info(
                    "DBUS PAIR: calling Pair() for %s on %s (timeout=30s, machine must be in Verbinden mode!)",
                    address, adapter,
                )
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
                        _LOGGER.info("DBUS PAIR: Pair() returned AlreadyExists, treating as success")
                        return True
                    _LOGGER.warning("DBUS PAIR: Pair() failed: %s (body=%s)", pair_reply.error_name, pair_reply.body)
                    return False

                _LOGGER.info("DBUS PAIR: Pair() succeeded for %s on %s", address, adapter)
                await asyncio.sleep(0.5)

                trust_reply = await bus.call(Message(
                    destination="org.bluez", path=dp,
                    interface="org.freedesktop.DBus.Properties",
                    member="Set", signature="ssv",
                    body=["org.bluez.Device1", "Trusted", Variant("b", True)],
                ))
                _LOGGER.debug("DBUS PAIR: Trusted set for %s (result=%s)", address,
                              "OK" if trust_reply.message_type != MessageType.ERROR else trust_reply.error_name)
                return True

            _LOGGER.warning("DBUS PAIR: no adapter found with device %s", address)
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
        _LOGGER.warning("DBUS PAIR: Pair() timed out (30s) for %s - is the machine in Verbinden mode?", address)
        return False
    except ImportError:
        _LOGGER.warning("DBUS PAIR: dbus_fast not available for pairing")
        return False
    except Exception as err:
        _LOGGER.warning("DBUS PAIR: error: %s (%s)", err, type(err).__name__)
        return False


async def dbus_check_bond_valid(address: str) -> bool:
    _LOGGER.debug("DBUS BOND CHECK: validating bond for %s", address)
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                paired = await _get_device_property(bus, dp, "Paired")
                if not paired:
                    _LOGGER.debug("DBUS BOND CHECK: not paired on %s, skipping", adapter)
                    continue
                connected = await _get_device_property(bus, dp, "Connected")
                _LOGGER.debug("DBUS BOND CHECK: %s on %s: Paired=%s, Connected=%s", address, adapter, paired, connected)
                if not connected:
                    _LOGGER.debug("DBUS BOND CHECK: device not connected, assuming valid bond (will verify on connect)")
                    return True
                for wait in range(6):
                    services_resolved = await _get_device_property(bus, dp, "ServicesResolved")
                    _LOGGER.debug("DBUS BOND CHECK: ServicesResolved=%s (poll %d/6)", services_resolved, wait + 1)
                    if services_resolved:
                        _LOGGER.info("DBUS BOND CHECK: ServicesResolved=True after %d polls, bond is valid", wait + 1)
                        return True
                    await asyncio.sleep(0.5)
                _LOGGER.warning("DBUS BOND CHECK: ServicesResolved still False after 3s - STALE BOND detected for %s", address)
                return False
            _LOGGER.debug("DBUS BOND CHECK: no paired adapter found, returning True")
            return True
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS BOND CHECK: error for %s: %s (%s)", address, err, type(err).__name__)
        return True


async def dbus_force_encryption(address: str) -> bool:
    _LOGGER.debug("DBUS ENCRYPT: forcing encryption for %s via Pair()", address)
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                _LOGGER.debug("DBUS ENCRYPT: calling Pair() on %s (timeout=5s)", dp)
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
                        _LOGGER.debug("DBUS ENCRYPT: encryption already active (AlreadyExists) for %s", address)
                        return True
                    _LOGGER.debug("DBUS ENCRYPT: Pair() error: %s for %s", reply.error_name, address)
                    return False
                _LOGGER.info("DBUS ENCRYPT: encryption activated for %s", address)
                return True
            _LOGGER.debug("DBUS ENCRYPT: no adapter found for %s", address)
            return False
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS ENCRYPT: error for %s: %s (%s)", address, err, type(err).__name__)
        return False


async def dbus_cancel_pairing(address: str):
    _LOGGER.debug("DBUS CANCEL PAIR: cancelling any active pairing for %s", address)
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                reply = await bus.call(Message(
                    destination="org.bluez", path=dp,
                    interface="org.bluez.Device1",
                    member="CancelPairing",
                ))
                if hasattr(reply, 'message_type') and reply.message_type == MessageType.ERROR:
                    _LOGGER.debug("DBUS CANCEL PAIR: %s (expected if not pairing)", reply.error_name)
                else:
                    _LOGGER.debug("DBUS CANCEL PAIR: succeeded for %s on %s", address, adapter)
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS CANCEL PAIR: error (expected if not pairing): %s", err)


async def dbus_force_disconnect(address: str):
    _LOGGER.debug("DBUS FORCE DISCONNECT: checking and disconnecting %s", address)
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            for adapter in await _get_adapters(bus):
                dp = _device_path(adapter, address)
                connected = await _get_device_property(bus, dp, "Connected")
                _LOGGER.debug("DBUS FORCE DISCONNECT: %s on %s: Connected=%s", address, adapter, connected)
                if connected:
                    await bus.call(Message(
                        destination="org.bluez", path=dp,
                        interface="org.bluez.Device1",
                        member="Disconnect",
                    ))
                    _LOGGER.info("DBUS FORCE DISCONNECT: disconnect sent for %s on %s, waiting 1s", address, adapter)
                    await asyncio.sleep(1.0)
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS FORCE DISCONNECT: error for %s: %s (%s)", address, err, type(err).__name__)


async def dbus_remove_device(address: str) -> bool:
    _LOGGER.info("DBUS REMOVE: removing device %s from BlueZ", address)
    try:
        from dbus_fast import Message, MessageType
        bus = await _get_bus()
        try:
            mac_path = address.replace(":", "_").upper()
            for adapter in await _get_adapters(bus):
                dp = f"/org/bluez/{adapter}/dev_{mac_path}"
                _LOGGER.debug("DBUS REMOVE: calling RemoveDevice on %s for %s", adapter, dp)
                reply = await bus.call(Message(
                    destination="org.bluez",
                    path=f"/org/bluez/{adapter}",
                    interface="org.bluez.Adapter1",
                    member="RemoveDevice",
                    signature="o",
                    body=[dp],
                ))
                if reply.message_type != MessageType.ERROR:
                    _LOGGER.info("DBUS REMOVE: RemoveDevice succeeded for %s on %s", address, adapter)
                    return True
                else:
                    _LOGGER.debug("DBUS REMOVE: RemoveDevice error on %s: %s", adapter, reply.error_name)
            _LOGGER.debug("DBUS REMOVE: device not found on any adapter")
            return False
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS REMOVE: error for %s: %s (%s)", address, err, type(err).__name__)
        return False


async def dbus_write_cccd(char_path: str) -> bool:
    _LOGGER.debug("DBUS CCCD: writing CCCD on %s", char_path)
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
                _LOGGER.debug("DBUS CCCD: introspect failed for %s: %s", char_path, introspect.error_name)
                return False

            descriptors = re.findall(r'<node name="(desc\w+)"', introspect.body[0]) if introspect.body else []
            _LOGGER.debug("DBUS CCCD: found %d descriptors on %s: %s", len(descriptors), char_path, descriptors)

            for desc_name in descriptors:
                desc_path = f"{char_path}/{desc_name}"
                uuid_reply = await bus.call(Message(
                    destination="org.bluez", path=desc_path,
                    interface="org.freedesktop.DBus.Properties",
                    member="Get", signature="ss",
                    body=["org.bluez.GattDescriptor1", "UUID"],
                ))
                if uuid_reply.message_type == MessageType.ERROR:
                    _LOGGER.debug("DBUS CCCD: UUID read failed for %s", desc_path)
                    continue
                desc_uuid = str(uuid_reply.body[0].value if uuid_reply.body else "")
                _LOGGER.debug("DBUS CCCD: descriptor %s UUID=%s", desc_name, desc_uuid)
                if desc_uuid.lower() == "00002902-0000-1000-8000-00805f9b34fb":
                    cccd_value = bytes([0x01, 0x00])
                    _LOGGER.debug("DBUS CCCD: found CCCD descriptor, writing 0x0100 to %s", desc_path)
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
                        _LOGGER.debug("DBUS CCCD: write error: %s", write_reply.error_name)
                        return False
                    _LOGGER.info("DBUS CCCD: descriptor written (0x0100) on %s", desc_path)
                    return True

            _LOGGER.debug("DBUS CCCD: no CCCD descriptor (0x2902) found on %s", char_path)
            return False
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS CCCD: error: %s (%s)", err, type(err).__name__)
        return False


async def dbus_check_notifying(char_path: str) -> bool:
    _LOGGER.debug("DBUS NOTIFY CHECK: checking Notifying property on %s", char_path)
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
                _LOGGER.debug("DBUS NOTIFY CHECK: error reading Notifying: %s", reply.error_name)
                return False
            val = reply.body[0] if reply.body else None
            if hasattr(val, 'value'):
                val = val.value
            result = bool(val)
            _LOGGER.debug("DBUS NOTIFY CHECK: Notifying=%s on %s", result, char_path)
            return result
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS NOTIFY CHECK: error: %s (%s)", err, type(err).__name__)
        return False


async def dbus_start_notify(char_path: str) -> bool:
    _LOGGER.debug("DBUS START NOTIFY: calling StartNotify on %s", char_path)
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
                _LOGGER.debug("DBUS START NOTIFY: error: %s on %s", reply.error_name, char_path)
                return False
            _LOGGER.info("DBUS START NOTIFY: succeeded on %s", char_path)
            return True
        finally:
            bus.disconnect()
    except Exception as err:
        _LOGGER.debug("DBUS START NOTIFY: error: %s (%s)", err, type(err).__name__)
        return False


async def dbus_register_notification_handler(char_path: str, data_callback):
    _LOGGER.debug("DBUS HANDLER: registering notification handler on %s", char_path)
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
    _LOGGER.info("DBUS HANDLER: notification handler registered on %s (match_rule=%s)", char_path, match_rule)
    return bus, on_message, match_rule


async def dbus_cleanup_notification_handler(bus, handler, match_rule):
    if bus is None:
        return
    _LOGGER.debug("DBUS CLEANUP: removing notification handler (match_rule=%s)", match_rule)
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
        _LOGGER.debug("CHAR PATH FROM SERVICES: no client")
        return None
    try:
        service_count = 0
        char_count = 0
        for service in client.services:
            service_count += 1
            for char in service.characteristics:
                char_count += 1
                if char.uuid.lower() == uuid.lower():
                    if hasattr(char, 'path'):
                        _LOGGER.debug("CHAR PATH FROM SERVICES: found %s via char.path=%s (services=%d, chars=%d)",
                                      uuid, char.path, service_count, char_count)
                        return char.path
                    if hasattr(char, 'obj') and hasattr(char.obj, 'get_object_path'):
                        path = char.obj.get_object_path()
                        _LOGGER.debug("CHAR PATH FROM SERVICES: found %s via obj.get_object_path()=%s", uuid, path)
                        return path
        _LOGGER.debug("CHAR PATH FROM SERVICES: UUID %s not found (searched %d services, %d chars)", uuid, service_count, char_count)
    except Exception as err:
        _LOGGER.debug("CHAR PATH FROM SERVICES: error: %s (%s)", err, type(err).__name__)
    return None


async def get_char_path_via_dbus(address: str, uuid: str) -> str | None:
    _LOGGER.debug("DBUS CHAR PATH: searching for UUID %s on device %s", uuid, address)
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
