import logging
import re
from typing import Any

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.data_entry_flow import FlowResult

from .const import (
    DOMAIN, CONF_MAC_ADDRESS, CONF_DEVICE_NAME, CONF_MODEL, SUPPORTED_MODELS,
    MELITTA_SERVICE_UUID, detect_model_from_name, is_melitta_machine_code,
)

_LOGGER = logging.getLogger(__name__)

MELITTA_KEYWORDS = ["melitta", "caffeo", "barista"]


def _is_melitta_device(name: str, service_uuids: list[str] | None = None) -> bool:
    if service_uuids and MELITTA_SERVICE_UUID.lower() in [
        u.lower() for u in service_uuids
    ]:
        return True
    if name and any(kw in name.lower() for kw in MELITTA_KEYWORDS):
        return True
    if is_melitta_machine_code(name):
        return True
    return False


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

        ble_name = self._discovery_info.name or ""
        auto_model = detect_model_from_name(ble_name) or "Barista Smart"
        default_name = auto_model if auto_model != "Barista Smart" else (ble_name or "Melitta Koffiezetapparaat")

        if user_input is not None:
            return self.async_create_entry(
                title=user_input.get(CONF_DEVICE_NAME, default_name),
                data={
                    CONF_MAC_ADDRESS: self._discovery_info.address,
                    CONF_DEVICE_NAME: user_input.get(CONF_DEVICE_NAME, default_name),
                    CONF_MODEL: user_input.get(CONF_MODEL, auto_model),
                },
            )

        self._set_confirm_only()
        placeholders = {
            "name": ble_name or "Melitta",
            "address": self._discovery_info.address,
        }
        self.context["title_placeholders"] = placeholders

        return self.async_show_form(
            step_id="bluetooth_confirm",
            data_schema=vol.Schema(
                {
                    vol.Optional(
                        CONF_DEVICE_NAME,
                        default=default_name,
                    ): str,
                    vol.Optional(CONF_MODEL, default=auto_model): vol.In(
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

                device_label = self._discovered_devices.get(address, "")
                device_name = device_label.lstrip("* ") if device_label else "Melitta Koffiezetapparaat"
                display_name = user_input.get(CONF_DEVICE_NAME, device_name)
                auto_model = detect_model_from_name(device_name) or "Barista Smart"

                return self.async_create_entry(
                    title=display_name,
                    data={
                        CONF_MAC_ADDRESS: address,
                        CONF_DEVICE_NAME: display_name,
                        CONF_MODEL: user_input.get(CONF_MODEL, auto_model),
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
                is_melitta = _is_melitta_device(name, discovery_info.service_uuids)
                detected_model = detect_model_from_name(name) if name else None
                display_name = name or discovery_info.address
                if is_melitta and detected_model:
                    display_name = f"{detected_model} ({name})"
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
                        is_melitta = _is_melitta_device(name)
                        detected_model = detect_model_from_name(name) if name else None
                        if is_melitta and detected_model:
                            display_name = f"{detected_model} ({name})"
                        else:
                            display_name = name
                        label = f"{'* ' if is_melitta else ''}{display_name}"
                        self._discovered_devices[device.address] = label
            except Exception as err:
                _LOGGER.warning("BLE scan failed: %s", err)

        if not self._discovered_devices:
            self._scan_failed = True
            return await self.async_step_manual()

        melitta_first = dict(
            sorted(
                self._discovered_devices.items(),
                key=lambda x: (0 if x[1].startswith("* ") else 1, x[1]),
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
