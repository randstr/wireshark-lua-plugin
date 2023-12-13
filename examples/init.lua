-- Code in this file will be run when the lua plugin loads.

local ws = require("wireshark")

ws.util.info("wslua2", "Loading \"init.lua\" using version %s and epan version %s", ws.VERSION, ws.EPAN_VERSION)
