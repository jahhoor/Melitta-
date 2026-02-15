import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import DOMAIN, CONF_MAC_ADDRESS, CONF_DEVICE_NAME, CONF_MODEL, SUPPORTED_MODELS, MELITTA_SERVICE_UUID

_LOGGER = logging.getLogger(__name__)

MELITTA_KEYWORDS = ["melitta", "caffeo", "barista"]
MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")


def normalize_mac(address: str) -> str:
    return address.strip().upper().replace("-", ":")


class MelittaCoffeeConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):

    VERSION = 1

    def __init__(self) -> None:
        self._discovery_info = None
        self._discovered_devices: dict[str, str] = {}
        self._scan_failed = False

    async def async_step_bluetooth(self, discovery_info) -> FlowResult:
        try:
            await self.async_set_unique_id(discovery_info.address)
            self._abort_if_unique_id_configured()
            self._discovery_info = discovery_info
            return await self.async_step_bluetooth_confirm()
        except Exception as err:
            _LOGGER.warning("Bluetooth discovery step failed: %s", err)
            return await self.async_step_user()

    async def async_step_bluetooth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        if self._discovery_info is None:
            return await self.async_step_user()

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
            "name": self._discovery_info.name or "Melitta",
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
            address = user_input.get(CONF_MAC_ADDRESS, "")
            if not address:
                errors["base"] = "no_devices_found"
            else:
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

        try:
            from homeassistant.components.bluetooth import async_discovered_service_info
            for discovery_info in async_discovered_service_info(self.hass, connectable=True):
                if discovery_info.address in current_addresses:
                    continue
                name = discovery_info.name or ""
                has_service_uuid = MELITTA_SERVICE_UUID.lower() in [
                    u.lower() for u in (discovery_info.service_uuids or [])
                ]
                is_melitta = has_service_uuid or (
                    name and any(kw in name.lower() for kw in MELITTA_KEYWORDS)
                )
                display_name = name or discovery_info.address
                label = f"{'* ' if is_melitta else ''}{display_name}"
                if is_melitta or name:
                    self._discovered_devices[discovery_info.address] = label
        except Exception as err:
            _LOGGER.warning("HA Bluetooth scan failed: %s", err)

        if not self._discovered_devices:
            try:
                from .device import discover_all_ble_devices
                bleak_devices = await discover_all_ble_devices(timeout=15.0)
                for device in bleak_devices:
                    if device.address not in current_addresses:
                        name = device.name or "Onbekend apparaat"
                        is_melitta = any(kw in name.lower() for kw in MELITTA_KEYWORDS)
                        label = f"{'* ' if is_melitta else ''}{name}"
                        self._discovered_devices[device.address] = label
            except Exception as err:
                _LOGGER.warning("BLE scan failed: %s", err)

        if not self._discovered_devices:
            self._scan_failed = True
            return await self.async_step_manual()

        melitta_first = dict(
            sorted(
                self._discovered_devices.items(),
                key=lambda x: (0 if any(kw in x[1].lower() for kw in MELITTA_KEYWORDS) else 1, x[1]),
            )
        )

        device_options = {
            address: f"{name} ({address})"
            for address, name in melitta_first.items()
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

        if self._scan_failed:
            errors["base"] = "no_devices_found"
            self._scan_failed = False

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
