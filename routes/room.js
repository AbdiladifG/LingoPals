const express = require("express");
const router = express.Router();
const roomsController = require("../controllers/room");
const { ensureAuth, ensureGuest } = require("../middleware/auth");

router.get("/:language", ensureAuth, roomsController.getRoom)

module.exports = router;