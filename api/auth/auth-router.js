const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require('bcryptjs')
const Users = require('../users/users-model')
const makeToken = require('./auth-token')

router.post("/register", validateRoleName, async (req, res, next) => {
    let user = req.body;
    const hash = bcrypt.hashSync(user.password, 8)
    user.password = hash
    user.role_name = req.role_name
    try {
      const reg = await Users.add(user)
      res.status(201).json(reg)
    } catch (error) {
      next(error)
    }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
    try {
      const user = req.user
      const token = makeToken(user)
      res.status(200).json({message: `${user.username} is back`, token: token})
    } catch (error) {
      next(error)
    }
});

module.exports = router;