-- Code in this file will be run when the lua plugin loads.

local ws = require("wireshark")

ws.util.log("wslua2", "info", "Loading \"init.lua\" using version %s and epan version %s", ws.VERSION, ws.EPAN_VERSION)
