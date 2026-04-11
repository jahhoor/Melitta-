"""Constants for the Melitta Barista Smart integration."""

from __future__ import annotations

from enum import IntEnum, IntFlag
from uuid import UUID

DOMAIN = "melitta_barista"

# ---------------------------------------------------------------------------
# Machine types
# ---------------------------------------------------------------------------

class MachineType(IntEnum):
    """Machine type IDs read via HR id=6."""
    BARISTA_T = 258
    BARISTA_TS = 259

MACHINE_TYPE_SETTING_ID = 6

BLE_PREFIXES_T: set[str] = {"8301", "8311", "8401"}
BLE_PREFIXES_TS: set[str] = {"8501", "8601", "8604"}
BLE_PREFIXES_ALL: set[str] = BLE_PREFIXES_T | BLE_PREFIXES_TS

MACHINE_MODEL_NAMES: dict[MachineType, str] = {
    MachineType.BARISTA_T: "Barista T Smart",
    MachineType.BARISTA_TS: "Barista TS Smart",
}

def detect_machine_type_from_name(device_name: str) -> MachineType | None:
    for prefix in BLE_PREFIXES_T:
        if device_name.startswith(prefix):
            return MachineType.BARISTA_T
    for prefix in BLE_PREFIXES_TS:
        if device_name.startswith(prefix):
            return MachineType.BARISTA_TS
    return None

# BLE GATT UUIDs
CHAR_NOTIFY = UUID("0000ad02-b35c-11e4-9813-0002a5d5c51b")
CHAR_WRITE = UUID("0000ad03-b35c-11e4-9813-0002a5d5c51b")

# Frame markers
FRAME_START = 0x53  # 'S'
FRAME_END = 0x45    # 'E'
FRAME_TIMEOUT = 5
BLE_MTU = 20

# Frame commands
CMD_ACK = "A"
CMD_NACK = "N"
CMD_READ_ALPHA = "HA"
CMD_WRITE_ALPHA = "HB"
CMD_READ_RECIPE = "HC"
CMD_START_PROCESS = "HE"
CMD_WRITE_RECIPE = "HJ"
CMD_READ_NUMERICAL = "HR"
CMD_READ_VERSION = "HV"
CMD_WRITE_NUMERICAL = "HW"
CMD_READ_STATUS = "HX"
CMD_CANCEL_PROCESS = "HZ"
CMD_HANDSHAKE = "HU"

# Protocol encryption keys (from Melitta Connect APK)
AES_KEY_PART_B = bytes([
    125, 57, 51, 41, 121, 78, -30 & 0xFF, 10,
    -62 & 0xFF, -22 & 0xFF, -27 & 0xFF, -19 & 0xFF,
    -89 & 0xFF, -85 & 0xFF, 3, 40, -12 & 0xFF,
])
AES_KEY_PART_A = bytes([
    99, -127 & 0xFF, 119, 125, 118, 101, -102 & 0xFF,
    -108 & 0xFF, -39 & 0xFF, 100, -61 & 0xFF,
    -117 & 0xFF, -95 & 0xFF, -65 & 0xFF, -14 & 0xFF,
])
AES_IV = bytes([
    -72 & 0xFF, -1 & 0xFF, -122 & 0xFF, -122 & 0xFF,
    64, -10 & 0xFF, 12, -118 & 0xFF, 25, 69,
    -117 & 0xFF, -123 & 0xFF, 58, -99 & 0xFF, 93, -2 & 0xFF,
])
ENCRYPTED_RC4_KEY = bytes([
    -81 & 0xFF, -14 & 0xFF, 21, -30 & 0xFF, 26, 60, 54, -89 & 0xFF,
    11, -42 & 0xFF, 95, -65 & 0xFF, 125, -6 & 0xFF, -99 & 0xFF, -111 & 0xFF,
    65, -16 & 0xFF, 14, 36, -126 & 0xFF, -40 & 0xFF, 13, -28 & 0xFF,
    15, 114, -48 & 0xFF, 48, -28 & 0xFF, -9 & 0xFF, -87 & 0xFF, 63,
    72, 122, -75 & 0xFF, 57, -13 & 0xFF, 101, 23, -7 & 0xFF,
    123, -9 & 0xFF, -66 & 0xFF, -30 & 0xFF, -87 & 0xFF, 5, -113 & 0xFF, -47 & 0xFF,
])


class MachineProcess(IntEnum):
    READY = 2
    PRODUCT = 4
    CLEANING = 9
    DESCALING = 10
    FILTER_INSERT = 11
    FILTER_REPLACE = 12
    FILTER_REMOVE = 13
    SWITCH_OFF = 16
    EASY_CLEAN = 17
    INTENSIVE_CLEAN = 19
    EVAPORATING = 20
    BUSY = 99


class SubProcess(IntEnum):
    GRINDING = 1
    COFFEE = 2
    STEAM = 3
    WATER = 4
    PREPARE = 5


class InfoMessage(IntFlag):
    FILL_BEANS_1 = 1 << 0
    FILL_BEANS_2 = 1 << 1
    EASY_CLEAN = 1 << 2
    POWDER_FILLED = 1 << 3
    PREPARATION_CANCELLED = 1 << 4


class Manipulation(IntEnum):
    NONE = 0
    BU_REMOVED = 1
    TRAYS_MISSING = 2
    EMPTY_TRAYS = 3
    FILL_WATER = 4
    CLOSE_POWDER_LID = 5
    FILL_POWDER = 6


class RecipeId(IntEnum):
    ESPRESSO = 200
    RISTRETTO = 201
    LUNGO = 202
    ESPRESSO_DOPIO = 203
    RISETTO_DOPIO = 204
    CAFE_CREME = 205
    CAFE_CREME_DOPIO = 206
    AMERICANO = 207
    AMERICANO_EXTRA = 208
    LONG_BLACK = 209
    RED_EYE = 210
    BLACK_EYE = 211
    DEAD_EYE = 212
    CAPPUCCINO = 213
    ESPR_MACCHIATO = 214
    CAFFE_LATTE = 215
    CAFE_AU_LAIT = 216
    FLAT_WHITE = 217
    LATTE_MACCHIATO = 218
    LATTE_MACCHIATO_EXTRA = 219
    LATTE_MACCHIATO_TRIPLE = 220
    MILK = 221
    MILK_FROTH = 222
    WATER = 223


RECIPE_NAMES: dict[int, str] = {
    RecipeId.ESPRESSO: "Espresso",
    RecipeId.RISTRETTO: "Ristretto",
    RecipeId.LUNGO: "Lungo",
    RecipeId.ESPRESSO_DOPIO: "Espresso Doppio",
    RecipeId.RISETTO_DOPIO: "Ristretto Doppio",
    RecipeId.CAFE_CREME: "Café Crème",
    RecipeId.CAFE_CREME_DOPIO: "Café Crème Doppio",
    RecipeId.AMERICANO: "Americano",
    RecipeId.AMERICANO_EXTRA: "Americano Extra",
    RecipeId.LONG_BLACK: "Long Black",
    RecipeId.RED_EYE: "Red Eye",
    RecipeId.BLACK_EYE: "Black Eye",
    RecipeId.DEAD_EYE: "Dead Eye",
    RecipeId.CAPPUCCINO: "Cappuccino",
    RecipeId.ESPR_MACCHIATO: "Espresso Macchiato",
    RecipeId.CAFFE_LATTE: "Caffè Latte",
    RecipeId.CAFE_AU_LAIT: "Café au Lait",
    RecipeId.FLAT_WHITE: "Flat White",
    RecipeId.LATTE_MACCHIATO: "Latte Macchiato",
    RecipeId.LATTE_MACCHIATO_EXTRA: "Latte Macchiato Extra",
    RecipeId.LATTE_MACCHIATO_TRIPLE: "Latte Macchiato Triple",
    RecipeId.MILK: "Milk",
    RecipeId.MILK_FROTH: "Milk Froth",
    RecipeId.WATER: "Hot Water",
}

TEMP_RECIPE_ID = 400
FREESTYLE_NAME_ID = 401
FREESTYLE_RECIPE_TYPE = 24

# TS-only recipes
TS_ONLY_RECIPES: set[int] = {
    RecipeId.RED_EYE,
    RecipeId.BLACK_EYE,
    RecipeId.DEAD_EYE,
}

BASE_RECIPES: list[int] = [r for r in RecipeId if r not in TS_ONLY_RECIPES]


def get_available_recipes(machine_type: MachineType | None) -> list[int]:
    if machine_type == MachineType.BARISTA_TS or machine_type is None:
        return list(RecipeId)
    return BASE_RECIPES


# RecipeType byte values
RECIPE_TYPE_MAP: dict[int, int] = {
    RecipeId.ESPRESSO: 0, RecipeId.RISTRETTO: 1, RecipeId.LUNGO: 2,
    RecipeId.ESPRESSO_DOPIO: 3, RecipeId.RISETTO_DOPIO: 4,
    RecipeId.CAFE_CREME: 5, RecipeId.CAFE_CREME_DOPIO: 6,
    RecipeId.AMERICANO: 7, RecipeId.AMERICANO_EXTRA: 8,
    RecipeId.LONG_BLACK: 9, RecipeId.RED_EYE: 10,
    RecipeId.BLACK_EYE: 11, RecipeId.DEAD_EYE: 12,
    RecipeId.CAPPUCCINO: 13, RecipeId.ESPR_MACCHIATO: 14,
    RecipeId.CAFFE_LATTE: 15, RecipeId.CAFE_AU_LAIT: 16,
    RecipeId.FLAT_WHITE: 17, RecipeId.LATTE_MACCHIATO: 18,
    RecipeId.LATTE_MACCHIATO_EXTRA: 19, RecipeId.LATTE_MACCHIATO_TRIPLE: 20,
    RecipeId.MILK: 21, RecipeId.MILK_FROTH: 22, RecipeId.WATER: 23,
}

RECIPE_TYPE_TO_KEY: dict[int, int] = {
    0: 0, 1: 0, 2: 0, 3: 0, 4: 0,
    5: 1, 6: 1, 7: 1, 8: 1, 9: 1,
    10: 1, 11: 1, 12: 1,
    13: 2, 14: 2, 15: 2, 16: 2, 17: 2,
    18: 3, 19: 3, 20: 3,
    21: 5,
    22: 4,
    23: 6,
    24: 7,
}


def get_recipe_key(recipe_type: int) -> int:
    return RECIPE_TYPE_TO_KEY.get(recipe_type, 7)


class ComponentProcess(IntEnum):
    NONE = 0
    COFFEE = 1
    STEAM = 2
    WATER = 3


class DirectKeyCategory(IntEnum):
    ESPRESSO = 0
    CAFE_CREME = 1
    CAPPUCCINO = 2
    LATTE_MACCHIATO = 3
    MILK_FROTH = 4
    MILK = 5
    WATER = 6


DIRECTKEY_OFFSET = 302
DIRECTKEY_PROFILE_MULTIPLIER = 10


def get_directkey_id(profile_id: int, category: DirectKeyCategory) -> int:
    return DIRECTKEY_OFFSET + profile_id * DIRECTKEY_PROFILE_MULTIPLIER + category


DIRECTKEY_DEFAULT_RECIPE_TYPE: dict[DirectKeyCategory, int] = {
    DirectKeyCategory.ESPRESSO: 0,
    DirectKeyCategory.CAFE_CREME: 5,
    DirectKeyCategory.CAPPUCCINO: 13,
    DirectKeyCategory.LATTE_MACCHIATO: 18,
    DirectKeyCategory.MILK_FROTH: 22,
    DirectKeyCategory.MILK: 21,
    DirectKeyCategory.WATER: 23,
}

PROFILE_NAMES = {0: "My Coffee"}
USER_NAME_IDS = {i: 310 + (i - 1) * 10 for i in range(1, 9)}
USER_ACTIVITY_IDS = {i: 311 + (i - 1) * 10 for i in range(1, 9)}

PROFILE_COUNTS: dict[MachineType, int] = {
    MachineType.BARISTA_T: 5,
    MachineType.BARISTA_TS: 9,
}


def get_user_profile_count(machine_type: MachineType | None) -> int:
    if machine_type is None:
        return 8
    total = PROFILE_COUNTS.get(machine_type, 5)
    return total - 1


CUP_COUNTER_BASE_ID = 100
TOTAL_CUPS_ID = 150

CUP_COUNTER_RECIPES: dict[int, str] = {
    0: "Espresso", 1: "Ristretto", 2: "Lungo",
    3: "Espresso Doppio", 4: "Ristretto Doppio",
    5: "Café Crème", 6: "Café Crème Doppio",
    7: "Americano", 8: "Americano Extra",
    9: "Long Black", 10: "Red Eye",
    11: "Black Eye", 12: "Dead Eye",
    13: "Cappuccino", 14: "Espresso Macchiato",
    15: "Caffè Latte", 16: "Café au Lait",
    17: "Flat White", 18: "Latte Macchiato",
    19: "Latte Macchiato Extra", 20: "Latte Macchiato Triple",
    21: "Milk", 22: "Milk Froth", 23: "Hot Water",
}

DEFAULT_POLL_INTERVAL: float = 5.0
DEFAULT_RECONNECT_DELAY: float = 5.0
DEFAULT_RECONNECT_MAX_DELAY: float = 300.0
DEFAULT_MAX_CONSECUTIVE_ERRORS: int = 10
DEFAULT_FRAME_TIMEOUT: int = 5
DEFAULT_BLE_CONNECT_TIMEOUT: float = 30.0
DEFAULT_PAIR_TIMEOUT: float = 30.0
DEFAULT_RECIPE_RETRIES: int = 3
DEFAULT_INITIAL_CONNECT_DELAY: float = 0.0

CONF_POLL_INTERVAL = "poll_interval"
CONF_RECONNECT_DELAY = "reconnect_initial_delay"
CONF_RECONNECT_MAX_DELAY = "reconnect_max_delay"
CONF_MAX_CONSECUTIVE_ERRORS = "max_consecutive_errors"
CONF_FRAME_TIMEOUT = "frame_timeout"
CONF_BLE_CONNECT_TIMEOUT = "ble_connect_timeout"
CONF_PAIR_TIMEOUT = "pair_timeout"
CONF_RECIPE_RETRIES = "recipe_retries"
CONF_INITIAL_CONNECT_DELAY = "initial_connect_delay"

PROCESS_MAP: dict[str, MachineProcess] = {
    "easy_clean": MachineProcess.EASY_CLEAN,
    "intensive_clean": MachineProcess.INTENSIVE_CLEAN,
    "descaling": MachineProcess.DESCALING,
    "filter_insert": MachineProcess.FILTER_INSERT,
    "filter_replace": MachineProcess.FILTER_REPLACE,
    "filter_remove": MachineProcess.FILTER_REMOVE,
    "evaporating": MachineProcess.EVAPORATING,
    "switch_off": MachineProcess.SWITCH_OFF,
}

INTENSITY_MAP: dict[str, int] = {
    "very_mild": 0, "mild": 1, "medium": 2, "strong": 3, "very_strong": 4,
}
AROMA_MAP: dict[str, int] = {"standard": 0, "intense": 1}
TEMPERATURE_MAP: dict[str, int] = {"cold": 0, "normal": 1, "high": 2}
SHOTS_MAP: dict[str, int] = {"none": 0, "one": 1, "two": 2, "three": 3}
