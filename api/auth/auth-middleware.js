const { default: jwtDecode } = require("jwt-decode");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const Users = require("../users/users-model");

const restricted = (req, res, next) => {
    const token = req.headers.authorization;
    if (!token) {
      return next({ status: 401, message: "Token required" });
    }
     jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
          next({ status: 401, message: "Token invalid" });
        } else {
          req.decodedToken = decoded;
          next();
        }
      });
  };

const only = (role_name) => (req, res, next) => {
    if (role_name === req.decodedToken.role_name) {
      next();
    } else {
      next({ status: 403, message: "This is not for you" });
    }
  };

const checkUsernameExists = async (req, res, next) => {
    try {
      const user = await Users.findBy({ username: req.body.username });
      if (
        user.length &&
        bcrypt.compareSync(req.body.password, user[0].password)
      ) {
        req.user = user[0];
        next();
      } else {
        next({ status: 401, message: "Invalid credentials" });
      }
    } catch (error) {
      next(error);
    }
  };


const validateRoleName = async (req, res, next) => {
    let role = req.body.role_name;
    if (!role || role.trim() === "") {
      req.role_name = "student";
      next();
    } else if (role.trim() === "admin") {
      next({ status: 422, message: "Role name can not be admin" });
    } else if (role.trim().length > 32) {
      next({ status: 422, message: "Role name can not be longer than 32 chars" });
    } else {
      req.role_name = role.trim();
      next();
    }
  };

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}