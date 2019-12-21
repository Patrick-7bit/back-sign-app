const Joi = require("@hapi/joi");

const registerValidation = data => {
  const schema = Joi.object({
    firstName: Joi.string()
      .min(6)
      .max(30)
      .required(),
    lastName: Joi.string()
      .min(6)
      .max(30)
      .required(),
    email: Joi.string().email({
      minDomainSegments: 2,
      tlds: { allow: ["com", "net"] }
    }),
    password: Joi.string().pattern(new RegExp("^[a-zA-Z0-9]{3,30}$"))
  });
  return Joi.assert(data, schema);
};

const loginValidation = data => {
  const schema = Joi.object({
    email: Joi.string().email({
      minDomainSegments: 2,
      tlds: { allow: ["com", "net"] }
    }),
    password: Joi.string().pattern(new RegExp("^[a-zA-Z0-9]{3,30}$"))
  });
  return Joi.assert(data, schema);
};

module.exports.registerValidation = registerValidation;
module.exports.loginValidation = loginValidation;
