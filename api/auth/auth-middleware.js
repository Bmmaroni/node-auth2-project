const { json } = require("express");
const jwt = require("jsonwebtoken")
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require("../users/users-model")
const roles = ["admin", "instructor", "student"]

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */
	return async (req, res, next) => {
		try {
			const token = req.header.authorization
			if (!token) {
				res.status(401).json({
					message: "Token required"
				})
			}

			jwt.verify(token, "keep it secret keep it safe", (err, decoded) => { // replace with secret variable
				if (err) {
					json.status(401).json({
						message: "Token invalid"
					})
				}

				req.token = decoded
				next()
			})
		} catch (err) {
			next(err)
		}
	}
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
	if (role_name && roles.indexOf(role_name) < roles.indexOf(req.token.role_name)) {
		res.status(403).json({
			message: "This is not for you"
		})
	}
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
	try {
		const { username } = req.body
		const checkName = await Users.findBy(username)
		if (checkName.length === 0) {
			return res.status(401).json({
				message: "Invalid credentials"
			})
		} else {
			next()
		}
	} catch (err) {
		next(err)
	}
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
	try {
		const rn = JSON.stringify(req.body.role_name)
		if (!rn || rn.trim() === "") {
			req.body.role_name = "student"
			next()
		} else if (rn.trim() === "admin") {
			return res.status(422).json({
				message: "Role name can not be admin"
			})
		} else if (rn.trim() > 32) {
			return res.status(422).json({
				message: "Role name can not be longer than 32 chars"
			})
		}

	} catch (err) {
		next(err)
	}
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
