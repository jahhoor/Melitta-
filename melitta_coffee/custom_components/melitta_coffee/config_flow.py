import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.components.bluetooth import (
    BluetoothServiceInfoBleak,
    async_discovered_service_info,
)
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, CONF_MAC_ADDRESS, CONF_DEVICE_NAME, CONF_MODEL, SUPPORTED_MODELS
from .device import discover_melitta_devices

_LOGGER = logging.getLogger(__name__)

MELITTA_KEYWORDS = ["melitta", "caffeo", "barista"]
MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def normalize_mac(address: str) -> str:
    return address.strip().upper().replace("-", ":")


class MelittaCoffeeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):

    VERSION = 1

    def __init__(self) -> None:
        self._discovery_info: BluetoothServiceInfoBleak | None = None
        self._discovered_devices: dict[str, str] = {}

    async def async_step_bluetooth(
        self, discovery_info: BluetoothServiceInfoBleak
    ) -> FlowResult:
        await self.async_set_unique_id(discovery_info.address)
        self._abort_if_unique_id_configured()
        self._discovery_info = discovery_info
        return await self.async_step_bluetooth_confirm()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        assert self._discovery_info is not None

        if user_input is not None:
            return self.async_create_entry(
                title=user_input.get(CONF_DEVICE_NAME, self._discovery_info.name),
                data={
                    CONF_MAC_ADDRESS: self._discovery_info.address,
                    CONF_DEVICE_NAME: user_input.get(CONF_DEVICE_NAME, self._discovery_info.name),
                    CONF_MODEL: user_input.get(CONF_MODEL, "Barista Smart"),
                },
            )

        self._set_confirm_only()
        placeholders = {
            "name": self._discovery_info.name,
            "address": self._discovery_info.address,
        }
        self.context["title_placeholders"] = placeholders

        return self.async_show_form(
            step_id="bluetooth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_DEVICE_NAME,
                        default=self._discovery_info.name or "Melitta Koffiezetapparaat",
                    ): str,
                    vol.Optional(CONF_MODEL, default="Barista Smart"): vol.In(
                        SUPPORTED_MODELS
                    ),
                }
            ),
            description_placeholders=placeholders,
        )

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        return self.async_show_menu(
            step_id="user",
            menu_options=["scan", "manual"],
        )

    async def async_step_scan(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None:
            address = user_input[CONF_MAC_ADDRESS]
            await self.async_set_unique_id(address, raise_on_progress=False)
            self._abort_if_unique_id_configured()

            device_name = self._discovered_devices.get(address, "Melitta Koffiezetapparaat")
            display_name = user_input.get(CONF_DEVICE_NAME, device_name)

            return self.async_create_entry(
                title=display_name,
                data={
                    CONF_MAC_ADDRESS: address,
                    CONF_DEVICE_NAME: display_name,
                    CONF_MODEL: user_input.get(CONF_MODEL, "Barista Smart"),
                },
            )

        current_addresses = self._async_current_ids()
        self._discovered_devices = {}

        for discovery_info in async_discovered_service_info(self.hass, connectable=True):
            name = discovery_info.name or ""
            if any(kw in name.lower() for kw in MELITTA_KEYWORDS):
                if discovery_info.address not in current_addresses:
                    self._discovered_devices[discovery_info.address] = name

        if not self._discovered_devices:
            try:
                bleak_devices = await discover_melitta_devices(timeout=15.0)
                for device in bleak_devices:
                    if device.address not in current_addresses:
                        self._discovered_devices[device.address] = device.name or "Melitta"
            except Exception as err:
                _LOGGER.warning("BLE scan failed: %s", err)

        if not self._discovered_devices:
            errors["base"] = "no_devices_found"
            return self.async_show_form(
                step_id="manual",
                data_schema=vol.Schema(
                    {
                        vol.Required(CONF_MAC_ADDRESS): str,
                        vol.Optional(
                            CONF_DEVICE_NAME, default="Melitta Koffiezetapparaat"
                        ): str,
                        vol.Optional(CONF_MODEL, default="Barista Smart"): vol.In(
                            SUPPORTED_MODELS
                        ),
                    }
                ),
                errors=errors,
            )

        device_options = {
            address: f"{name} ({address})"
            for address, name in self._discovered_devices.items()
        }

        return self.async_show_form(
            step_id="scan",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MAC_ADDRESS): vol.In(device_options),
                    vol.Optional(
                        CONF_DEVICE_NAME, default="Melitta Koffiezetapparaat"
                    ): str,
                    vol.Optional(CONF_MODEL, default="Barista Smart"): vol.In(
                        SUPPORTED_MODELS
                    ),
                }
            ),
            errors=errors,
        )

    async def async_step_manual(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        errors: dict[str, str] = {}

        if user_input is not None and CONF_MAC_ADDRESS in user_input:
            address = normalize_mac(user_input[CONF_MAC_ADDRESS])

            if not MAC_PATTERN.match(address):
                errors[CONF_MAC_ADDRESS] = "invalid_mac"
            else:
                await self.async_set_unique_id(address, raise_on_progress=False)
                self._abort_if_unique_id_configured()

                return self.async_create_entry(
                    title=user_input.get(CONF_DEVICE_NAME, "Melitta Koffiezetapparaat"),
                    data={
                        CONF_MAC_ADDRESS: address,
                        CONF_DEVICE_NAME: user_input.get(
                            CONF_DEVICE_NAME, "Melitta Koffiezetapparaat"
                        ),
                        CONF_MODEL: user_input.get(CONF_MODEL, "Barista Smart"),
                    },
                )

        return self.async_show_form(
            step_id="manual",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_MAC_ADDRESS): str,
                    vol.Optional(
                        CONF_DEVICE_NAME, default="Melitta Koffiezetapparaat"
                    ): str,
                    vol.Optional(CONF_MODEL, default="Barista Smart"): vol.In(
                        SUPPORTED_MODELS
                    ),
                }
            ),
            errors=errors,
        )
