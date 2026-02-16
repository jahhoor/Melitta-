import logging
import voluptuous as vol
from homeassistant import config_entries
from homeassistant.components.bluetooth import async_discovered_service_info
from homeassistant.const import CONF_ADDRESS
from .const import DOMAIN, CONF_MAC_ADDRESS, SUPPORTED_MACHINE_CODES, MACHINE_CODE_NAMES

_LOGGER = logging.getLogger(__name__)

STEP_USER_DATA_SCHEMA = vol.Schema({
    vol.Required(CONF_MAC_ADDRESS): str,
})


class MelittaCoffeeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self):
        self._discovered_devices = {}

    async def async_step_user(self, user_input=None):
        errors = {}

        if user_input is not None:
            mac = user_input[CONF_MAC_ADDRESS].upper().strip()
            await self.async_set_unique_id(mac)
            self._abort_if_unique_id_configured()

            name = self._discovered_devices.get(mac, f"Melitta Coffee ({mac})")

            return self.async_create_entry(
                title=name,
                data={CONF_MAC_ADDRESS: mac},
            )

        self._discovered_devices = {}
        try:
            for info in async_discovered_service_info(self.hass):
                if info.name:
                    for code in SUPPORTED_MACHINE_CODES:
                        if code in info.name:
                            model = MACHINE_CODE_NAMES.get(code, "Melitta Coffee Machine")
                            self._discovered_devices[info.address.upper()] = f"{model} ({info.address})"
                            break
        except Exception:
            pass

        if self._discovered_devices:
            schema = vol.Schema({
                vol.Required(CONF_MAC_ADDRESS): vol.In(self._discovered_devices),
            })
        else:
            schema = STEP_USER_DATA_SCHEMA

        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            errors=errors,
            description_placeholders={
                "instruction": "Enter the MAC address of your Melitta coffee machine or select a discovered device. Make sure Bluetooth is enabled and the machine is on."
            },
        )

    async def async_step_bluetooth(self, discovery_info):
        address = discovery_info.address.upper()
        name = discovery_info.name or ""

        is_melitta = False
        model_name = "Melitta Coffee Machine"
        for code in SUPPORTED_MACHINE_CODES:
            if code in name:
                is_melitta = True
                model_name = MACHINE_CODE_NAMES.get(code, model_name)
                break

        if not is_melitta:
            return self.async_abort(reason="not_supported")

        await self.async_set_unique_id(address)
        self._abort_if_unique_id_configured()

        self.context["title_placeholders"] = {"name": model_name}
        self._discovered_devices = {address: f"{model_name} ({address})"}

        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(self, user_input=None):
        if user_input is not None:
            address = list(self._discovered_devices.keys())[0]
            name = self._discovered_devices[address]
            return self.async_create_entry(
                title=name,
                data={CONF_MAC_ADDRESS: address},
            )

        return self.async_show_form(
            step_id="bluetooth_confirm",
            description_placeholders={
                "name": list(self._discovered_devices.values())[0],
            },
        )
