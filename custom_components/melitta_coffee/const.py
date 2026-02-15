DOMAIN = "melitta_coffee"
CONF_MAC_ADDRESS = "mac_address"
CONF_DEVICE_NAME = "device_name"
CONF_MODEL = "model"

DEFAULT_NAME = "Melitta Koffiezetapparaat"

MELITTA_SERVICE_UUID = "0000ad01-b35c-11e4-9813-0002a5d5c51b"
MELITTA_READ_CHAR_UUID = "0000ad02-b35c-11e4-9813-0002a5d5c51b"
MELITTA_WRITE_CHAR_UUID = "0000ad03-b35c-11e4-9813-0002a5d5c51b"

SUPPORTED_MACHINE_CODES_T = {"8301", "8311", "8401"}
SUPPORTED_MACHINE_CODES_TS = {"8501", "8601", "8604"}
SUPPORTED_MACHINE_CODES = SUPPORTED_MACHINE_CODES_T | SUPPORTED_MACHINE_CODES_TS

MACHINE_CODE_TO_MODEL = {
    "8301": "Caffeo Barista T",
    "8311": "Caffeo Barista T",
    "8401": "Barista T Smart",
    "8501": "Caffeo Barista TS",
    "8601": "Barista TS Smart",
    "8604": "Barista TS Smart",
}

SUPPORTED_MODELS = [
    "Barista Smart",
    "Barista T Smart",
    "Barista TS Smart",
    "Caffeo Barista T",
    "Caffeo Barista TS",
]


def detect_model_from_name(ble_name: str) -> str | None:
    if ble_name and len(ble_name) >= 4:
        prefix = ble_name[:4]
        return MACHINE_CODE_TO_MODEL.get(prefix)
    return None


def is_melitta_machine_code(name: str) -> bool:
    if name and len(name) >= 4:
        return name[:4] in SUPPORTED_MACHINE_CODES
    return False

FRAME_START = 0x53
FRAME_END = 0x45
FRAME_MAX_SIZE = 128
BLE_MTU_SIZE = 20

CMD_AUTH = "G\x02"
CMD_KEEPALIVE = "G\x01"
CMD_BREW = "HJ"
CMD_WRITE_VALUE = "HW"
CMD_READ_VALUE = "HR"
CMD_SET_PROCESS = "HZ"
CMD_STATUS = "HX"
CMD_RECIPE_CONFIRM = "HC"
CMD_ALPHA_VALUE = "HA"
CMD_VERSION = "HV"
CMD_ACK = "A"
CMD_NACK = "N"

KEEPALIVE_INTERVAL = 55

SBOX = bytes([
    98, 6, 85, -106 & 0xFF, 36, 23, 112, -92 & 0xFF, -121 & 0xFF, -49 & 0xFF,
    -87 & 0xFF, 5, 26, 64, -91 & 0xFF, -37 & 0xFF, 61, 20, 68, 89,
    -126 & 0xFF, 63, 52, 102, 24, -27 & 0xFF, -124 & 0xFF, -11 & 0xFF, 80, -40 & 0xFF,
    -61 & 0xFF, 115, 90, -88 & 0xFF, -100 & 0xFF, -53 & 0xFF, -79 & 0xFF, 120, 2, -66 & 0xFF,
    -68 & 0xFF, 7, 100, -71 & 0xFF, -82 & 0xFF, -13 & 0xFF, -94 & 0xFF, 10, -19 & 0xFF, 18,
    -3 & 0xFF, -31 & 0xFF, 8, -48 & 0xFF, -84 & 0xFF, -12 & 0xFF, -1 & 0xFF, 126, 101, 79,
    -111 & 0xFF, -21 & 0xFF, -28 & 0xFF, 121, 123, -5 & 0xFF, 67, -6 & 0xFF, -95 & 0xFF, 0,
    107, 97, -15 & 0xFF, 111, -75 & 0xFF, 82, -7 & 0xFF, 33, 69, 55,
    59, -103 & 0xFF, 29, 9, -43 & 0xFF, -89 & 0xFF, 84, 93, 30, 46,
    94, 75, -105 & 0xFF, 114, 73, -34 & 0xFF, -59 & 0xFF, 96, -46 & 0xFF, 45,
    16, -29 & 0xFF, -8 & 0xFF, -54 & 0xFF, 51, -104 & 0xFF, -4 & 0xFF, 125, 81, -50 & 0xFF,
    -41 & 0xFF, -70 & 0xFF, 39, -98 & 0xFF, -78 & 0xFF, -69 & 0xFF, -125 & 0xFF, -120 & 0xFF, 1, 49,
    50, 17, -115 & 0xFF, 91, 47, -127 & 0xFF, 60, 99, -102 & 0xFF, 35,
    86, -85 & 0xFF, 105, 34, 38, -56 & 0xFF, -109 & 0xFF, 58, 77, 118,
    -83 & 0xFF, -10 & 0xFF, 76, -2 & 0xFF, -123 & 0xFF, -24 & 0xFF, -60 & 0xFF, -112 & 0xFF, -58 & 0xFF, 124,
    53, 4, 108, 74, -33 & 0xFF, -22 & 0xFF, -122 & 0xFF, -26 & 0xFF, -99 & 0xFF, -117 & 0xFF,
    -67 & 0xFF, -51 & 0xFF, -57 & 0xFF, -128 & 0xFF, -80 & 0xFF, 19, -45 & 0xFF, -20 & 0xFF, 127, -64 & 0xFF,
    -25 & 0xFF, 70, -23 & 0xFF, 88, -110 & 0xFF, 44, -73 & 0xFF, -55 & 0xFF, 22, 83,
    13, -42 & 0xFF, 116, 109, -97 & 0xFF, 32, 95, -30 & 0xFF, -116 & 0xFF, -36 & 0xFF,
    57, 12, -35 & 0xFF, 31, -47 & 0xFF, -74 & 0xFF, -113 & 0xFF, 92, -107 & 0xFF, -72 & 0xFF,
    -108 & 0xFF, 62, 113, 65, 37, 27, 106, -90 & 0xFF, 3, 14,
    -52 & 0xFF, 72, 21, 41, 56, 66, 28, -63 & 0xFF, 40, -39 & 0xFF,
    25, 54, -77 & 0xFF, 117, -18 & 0xFF, 87, -16 & 0xFF, -101 & 0xFF, -76 & 0xFF, -86 & 0xFF,
    -14 & 0xFF, -44 & 0xFF, -65 & 0xFF, -93 & 0xFF, 78, -38 & 0xFF, -119 & 0xFF, -62 & 0xFF, -81 & 0xFF, 110,
    43, 119, -32 & 0xFF, 71, 122, -114 & 0xFF, 42, -96 & 0xFF, 104, 48,
    -9 & 0xFF, 103, 15, 11, -118 & 0xFF, -17 & 0xFF,
])

ENCRYPTION_KEY_48 = bytes([
    0xAF, 0xF2, 0x15, 0xE2, 0x1A, 0x3C, 0x36, 0xA7,
    0x0B, 0xD6, 0x5F, 0xBF, 0x7D, 0xFA, 0x9D, 0x91,
    0x41, 0xF0, 0x0E, 0x24, 0x82, 0xD8, 0x0D, 0xE4,
    0x0F, 0x72, 0xD0, 0x30, 0xE4, 0xF7, 0xA9, 0x3F,
    0x48, 0x7A, 0xB5, 0x39, 0xF3, 0x65, 0x17, 0xF9,
    0x7B, 0xF7, 0xBE, 0xE2, 0xA9, 0x05, 0x8F, 0xD1,
])

ENCRYPTION_KEY_32 = bytes([
    0x83, 0x4A, 0x3E, 0x98, 0x0D, 0x65, 0xFA, 0xCC,
    0x59, 0x46, 0xB9, 0x44, 0x28, 0x24, 0x07, 0x2D,
    0xB0, 0xD7, 0x7D, 0xD0, 0xBE, 0x09, 0x83, 0xB3,
    0xCA, 0xEE, 0x0A, 0xAF, 0x94, 0x72, 0xA9, 0x24,
])

class Process:
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

PROCESS_MAP = {
    Process.READY: "ready",
    Process.PRODUCT: "brewing",
    Process.CLEANING: "cleaning",
    Process.DESCALING: "descaling",
    Process.FILTER_INSERT: "filter_insert",
    Process.FILTER_REPLACE: "filter_replace",
    Process.FILTER_REMOVE: "filter_remove",
    Process.SWITCH_OFF: "switch_off",
    Process.EASY_CLEAN: "easy_clean",
    Process.INTENSIVE_CLEAN: "intensive_clean",
    Process.EVAPORATING: "evaporating",
    Process.BUSY: "busy",
}

class SubProcess:
    GRINDING = 1
    COFFEE = 2
    STEAM = 3
    WATER = 4
    PREPARE = 5

SUBPROCESS_MAP = {
    SubProcess.GRINDING: "grinding",
    SubProcess.COFFEE: "coffee",
    SubProcess.STEAM: "steam",
    SubProcess.WATER: "water",
    SubProcess.PREPARE: "prepare",
}

class Manipulation:
    NONE = 0
    BU_REMOVED = 1
    TRAYS_MISSING = 2
    EMPTY_TRAYS = 3
    FILL_WATER = 4
    CLOSE_POWDER_LID = 5
    FILL_POWDER = 6

MANIPULATION_MAP = {
    Manipulation.NONE: None,
    Manipulation.BU_REMOVED: "brewing_unit_removed",
    Manipulation.TRAYS_MISSING: "drip_tray_missing",
    Manipulation.EMPTY_TRAYS: "empty_drip_tray",
    Manipulation.FILL_WATER: "fill_water",
    Manipulation.CLOSE_POWDER_LID: "close_powder_lid",
    Manipulation.FILL_POWDER: "fill_powder",
}

class InfoFlag:
    FILL_BEANS_1 = 0
    FILL_BEANS_2 = 1
    EASY_CLEAN = 2
    POWDER_FILLED = 3
    PREPARATION_CANCELLED = 4

class RecipeProcess:
    NONE = 0
    COFFEE = 1
    STEAM = 2
    WATER = 3
    WARM_MILK = 2

class Shots:
    NONE = 0
    ONE = 1
    TWO = 2
    THREE = 3

class Blend:
    BARISTA_T = 0
    BLEND_1 = 1
    BLEND_2 = 2

class Intensity:
    VERY_MILD = 0
    MILD = 1
    MEDIUM = 2
    STRONG = 3
    VERY_STRONG = 4

class Aroma:
    STANDARD = 0
    INTENSE = 1

class Temperature:
    COLD = 0
    NORMAL = 1
    HIGH = 2

BEVERAGE_MAP = {
    "espresso":               0,
    "ristretto":              1,
    "lungo":                  2,
    "espresso_doppio":        3,
    "ristretto_doppio":       4,
    "cafe_creme":             5,
    "cafe_creme_doppio":      6,
    "americano":              7,
    "americano_extra":        8,
    "long_black":             9,
    "red_eye":                10,
    "black_eye":              11,
    "dead_eye":               12,
    "cappuccino":             13,
    "espresso_macchiato":     14,
    "caffe_latte":            15,
    "cafe_au_lait":           16,
    "flat_white":             17,
    "latte_macchiato":        18,
    "latte_macchiato_extra":  19,
    "latte_macchiato_triple": 20,
    "milk":                   21,
    "milk_froth":             22,
    "hot_water":              23,
    "freestyle":              24,
}

BEVERAGE_NAMES = {v: k for k, v in BEVERAGE_MAP.items()}

DIRECT_KEY_MAP = {
    "espresso": 0,
    "coffee": 1,
    "cappuccino": 2,
    "macchiato": 3,
    "milk_froth": 4,
    "milk": 5,
    "water": 6,
    "menu": 7,
}

BEVERAGE_TO_DIRECT_KEY = {
    "espresso": "espresso",
    "ristretto": "espresso",
    "lungo": "espresso",
    "espresso_doppio": "espresso",
    "ristretto_doppio": "espresso",
    "cafe_creme": "coffee",
    "cafe_creme_doppio": "coffee",
    "americano": "coffee",
    "americano_extra": "coffee",
    "long_black": "coffee",
    "red_eye": "coffee",
    "black_eye": "coffee",
    "dead_eye": "coffee",
    "cappuccino": "cappuccino",
    "espresso_macchiato": "macchiato",
    "caffe_latte": "macchiato",
    "cafe_au_lait": "macchiato",
    "flat_white": "macchiato",
    "latte_macchiato": "macchiato",
    "latte_macchiato_extra": "macchiato",
    "latte_macchiato_triple": "macchiato",
    "milk": "milk",
    "milk_froth": "milk_froth",
    "hot_water": "water",
}

STRENGTH_MAP = {
    "very_mild": Intensity.VERY_MILD,
    "mild": Intensity.MILD,
    "medium": Intensity.MEDIUM,
    "strong": Intensity.STRONG,
    "very_strong": Intensity.VERY_STRONG,
}

STRENGTH_NAMES = {v: k for k, v in STRENGTH_MAP.items()}

DEFAULT_RECIPES = {
    "espresso":               {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 40},
    "ristretto":              {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.STRONG, "portion": 25},
    "lungo":                  {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 120},
    "espresso_doppio":        {"process": RecipeProcess.COFFEE, "shots": Shots.TWO,   "intensity": Intensity.MEDIUM, "portion": 80},
    "ristretto_doppio":       {"process": RecipeProcess.COFFEE, "shots": Shots.TWO,   "intensity": Intensity.STRONG, "portion": 50},
    "cafe_creme":             {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 120},
    "cafe_creme_doppio":      {"process": RecipeProcess.COFFEE, "shots": Shots.TWO,   "intensity": Intensity.MEDIUM, "portion": 240},
    "americano":              {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 40},
    "americano_extra":        {"process": RecipeProcess.COFFEE, "shots": Shots.TWO,   "intensity": Intensity.MEDIUM, "portion": 40},
    "long_black":             {"process": RecipeProcess.COFFEE, "shots": Shots.TWO,   "intensity": Intensity.MEDIUM, "portion": 40},
    "red_eye":                {"process": RecipeProcess.COFFEE, "shots": Shots.TWO,   "intensity": Intensity.STRONG, "portion": 120},
    "black_eye":              {"process": RecipeProcess.COFFEE, "shots": Shots.THREE, "intensity": Intensity.STRONG, "portion": 120},
    "dead_eye":               {"process": RecipeProcess.COFFEE, "shots": Shots.THREE, "intensity": Intensity.VERY_STRONG, "portion": 120},
    "cappuccino":             {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 40},
    "espresso_macchiato":     {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 40},
    "caffe_latte":            {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 40},
    "cafe_au_lait":           {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MILD,   "portion": 60},
    "flat_white":             {"process": RecipeProcess.COFFEE, "shots": Shots.TWO,   "intensity": Intensity.STRONG, "portion": 40},
    "latte_macchiato":        {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 40},
    "latte_macchiato_extra":  {"process": RecipeProcess.COFFEE, "shots": Shots.TWO,   "intensity": Intensity.MEDIUM, "portion": 40},
    "latte_macchiato_triple": {"process": RecipeProcess.COFFEE, "shots": Shots.THREE, "intensity": Intensity.MEDIUM, "portion": 40},
    "milk":                   {"process": RecipeProcess.STEAM,  "shots": Shots.NONE,  "intensity": Intensity.MEDIUM, "portion": 100},
    "milk_froth":             {"process": RecipeProcess.STEAM,  "shots": Shots.NONE,  "intensity": Intensity.MEDIUM, "portion": 100},
    "hot_water":              {"process": RecipeProcess.WATER,  "shots": Shots.NONE,  "intensity": Intensity.MEDIUM, "portion": 200},
    "freestyle":              {"process": RecipeProcess.COFFEE, "shots": Shots.ONE,   "intensity": Intensity.MEDIUM, "portion": 40},
}

SCAN_INTERVAL = 30
CONNECT_TIMEOUT = 20
DISCONNECT_TIMEOUT = 5
