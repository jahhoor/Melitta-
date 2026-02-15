DOMAIN = "melitta_coffee"
CONF_MAC_ADDRESS = "mac_address"
CONF_DEVICE_NAME = "device_name"
CONF_MODEL = "model"

DEFAULT_NAME = "Melitta Koffiezetapparaat"

MELITTA_SERVICE_UUID = "0000fff0-0000-1000-8000-00805f9b34fb"
MELITTA_CONTROL_CHAR_UUID = "0000fff1-0000-1000-8000-00805f9b34fb"
MELITTA_STATUS_CHAR_UUID = "0000fff2-0000-1000-8000-00805f9b34fb"
MELITTA_NOTIFY_CHAR_UUID = "0000fff3-0000-1000-8000-00805f9b34fb"

SUPPORTED_MODELS = [
    "Barista Smart",
    "Barista T Smart",
    "Barista TS Smart",
    "Caffeo Barista T",
    "Caffeo Barista TS",
]

MACHINE_STATUS_MAP = {
    0x00: "standby",
    0x01: "idle",
    0x02: "brewing",
    0x03: "grinding",
    0x04: "heating",
    0x05: "cleaning",
    0x06: "error",
    0x07: "descaling",
    0x08: "rinsing",
}

STRENGTH_MAP = {
    "mild": 0x01,
    "medium": 0x02,
    "strong": 0x03,
    "extra_strong": 0x04,
}

BEVERAGE_MAP = {
    "espresso": 0x01,
    "coffee": 0x02,
    "cappuccino": 0x03,
    "latte_macchiato": 0x04,
    "lungo": 0x05,
    "hot_water": 0x06,
    "steam": 0x07,
}

WATER_LEVEL_MAP = {
    0x00: "empty",
    0x01: "low",
    0x02: "medium",
    0x03: "full",
}

BEAN_LEVEL_MAP = {
    0x00: "empty",
    0x01: "low",
    0x02: "medium",
    0x03: "full",
}

ERROR_MAP = {
    0x01: "water_tank_empty",
    0x02: "bean_container_empty",
    0x03: "drip_tray_full",
    0x04: "waste_container_full",
    0x05: "descaling_needed",
    0x06: "brewing_unit_missing",
    0x07: "general_error",
}

SCAN_INTERVAL = 30
CONNECT_TIMEOUT = 10
DISCONNECT_TIMEOUT = 5
