import logging
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import DOMAIN, CONF_MAC_ADDRESS
from .device import MelittaDevice

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
):
    device: MelittaDevice = hass.data[DOMAIN][entry.entry_id]
    entities = [
        MelittaStatusSensor(device, entry),
        MelittaMachineStateSensor(device, entry),
        MelittaWaterLevelSensor(device, entry),
        MelittaBeanLevelSensor(device, entry),
        MelittaBrewProgressSensor(device, entry),
    ]
    async_add_entities(entities)


class MelittaBaseSensor(SensorEntity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        self._device = device
        self._entry = entry
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.data[CONF_MAC_ADDRESS])},
            "name": device.name,
            "manufacturer": "Melitta",
            "model": "Caffeo Barista",
        }
        self._remove_callback = None

    async def async_added_to_hass(self):
        self._remove_callback = self._device.register_callback(self._handle_update)

    async def async_will_remove_from_hass(self):
        if self._remove_callback:
            self._remove_callback()

    @callback
    def _handle_update(self):
        self.async_write_ha_state()


class MelittaStatusSensor(MelittaBaseSensor):
    _attr_should_poll = True

    STATUS_MAP = {
        "offline": "Offline",
        "connecting": "Connecting...",
        "authenticating": "Authenticating...",
        "ready": "Ready",
        "connected_not_auth": "Connected, waiting for pairing",
        "auth_dropped": "Connection dropped during auth",
    }

    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_status"
        self._attr_name = "Status"
        self._attr_icon = "mdi:coffee-maker"

    @property
    def native_value(self) -> str:
        return self.STATUS_MAP.get(self._device.status, self._device.status)

    async def async_update(self):
        await self._device.async_update()


class MelittaMachineStateSensor(MelittaBaseSensor):
    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_machine_state"
        self._attr_name = "Machine State"
        self._attr_icon = "mdi:state-machine"

    @property
    def native_value(self) -> str:
        return self._device.machine_state_name

    @property
    def extra_state_attributes(self):
        attrs = {}
        if self._device.machine_state is not None:
            attrs["state_code"] = self._device.machine_state
        if self._device.last_error:
            attrs["last_error"] = self._device.last_error
        if self._device.error_code is not None:
            attrs["error_code"] = self._device.error_code
        return attrs


class MelittaWaterLevelSensor(MelittaBaseSensor):
    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_water_level"
        self._attr_name = "Water Level"
        self._attr_icon = "mdi:water"
        self._attr_native_unit_of_measurement = "%"

    @property
    def native_value(self) -> int | None:
        return self._device.water_level

    @property
    def available(self) -> bool:
        return self._device.is_authenticated and self._device.water_level is not None


class MelittaBeanLevelSensor(MelittaBaseSensor):
    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_bean_level"
        self._attr_name = "Bean Level"
        self._attr_icon = "mdi:seed"
        self._attr_native_unit_of_measurement = "%"

    @property
    def native_value(self) -> int | None:
        return self._device.bean_level

    @property
    def available(self) -> bool:
        return self._device.is_authenticated and self._device.bean_level is not None


class MelittaBrewProgressSensor(MelittaBaseSensor):
    def __init__(self, device: MelittaDevice, entry: ConfigEntry):
        super().__init__(device, entry)
        self._attr_unique_id = f"{entry.data[CONF_MAC_ADDRESS]}_brew_progress"
        self._attr_name = "Brew Progress"
        self._attr_icon = "mdi:progress-clock"
        self._attr_native_unit_of_measurement = "%"

    @property
    def native_value(self) -> int | None:
        return self._device.brew_progress

    @property
    def available(self) -> bool:
        return self._device.is_authenticated
