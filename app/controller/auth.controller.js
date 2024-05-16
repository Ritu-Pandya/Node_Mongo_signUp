const db = require("../models");
const User = db.user;
const Role = db.role;
const RefreshToken = db.refreshToken;
var bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("../config/auth.config")

exports.signup = (req, res) => {
  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: bcrypt.hashSync(req.body.password, 8)
  });

  user.save().then(user => {
    if (req.body.roles) {
      Role.find(
        {
          name: { $in: req.body.roles }
        })
        .then( roles => {
         
          user.roles = roles.map(role => role._id);
          user.save(err => {
            if (err) {
              res.status(500).send({ message: err });
              return;
            }

            res.status(201).send({ message: "User was registered successfully!" });
          });
        }
      );
    } else {
      Role.findOne({ name: "user" }).then(role => {
       
        user.roles = [role._id];
        user.save().then(y => {
         
          res.status(201).send({ message: "User was registered successfully!" });
          return;
        });
      });
    }
  });
};

exports.signin = (req, res) => {

  console.log(req.body.username);
  User.findOne({
    username: req.body.username
  })
    .populate("roles", "-__v")
    .exec()
    .then(user => {


        console.log(user);
        if (!user) {
          return res.status(404).send({ message: "User Not found." });
        }
      var passwordIsValid = bcrypt.compareSync(
        req.body.password,
        user.password
      );

      if (!passwordIsValid) {
        return res.status(401).send({
          accessToken: null,
          message: "Invalid Password!"
        });
      }

      const token = jwt.sign({ id: user.id },
                              config.secret,
                              {
                                algorithm: 'HS256',
                                allowInsecureKeySizes: true,
                                expiresIn: 86400, // 24 hours
                              });

                              let refreshTokenPromise = RefreshToken.createToken(user);

                              let authorities = user.roles.map(role => "ROLE_" + role.name.toUpperCase());
                        
                              refreshTokenPromise.then(refreshToken => {
                                res.status(200).send({
                                  id: user._id,
                                  username: user.username,
                                  email: user.email,
                                  roles: authorities,
                                  accessToken: token,
                                  refreshToken: refreshToken,
                                });
                              }).catch(err => {
                                res.status(500).send({ message: err });
                              });
                            }).catch(err => {
                              res.status(500).send({ message: err });
                            });
                        };

                        exports.refreshToken = (req, res) => {
                          const { refreshToken: requestToken } = req.body;
                        
                          if (requestToken == null) {
                            return res.status(403).json({ message: "Refresh Token is required!" });
                          }
                        
                          RefreshToken.findOne({ token: requestToken })
                            .then(refreshToken => {
                              if (!refreshToken) {
                                return res.status(403).json({ message: "Refresh token is not in database!" });
                              }
                        
                              if (RefreshToken.verifyExpiration(refreshToken)) {
                                RefreshToken.findByIdAndRemove(refreshToken._id, { useFindAndModify: false }).exec();
                        
                                return res.status(403).json({
                                  message: "Refresh token was expired. Please make a new signin request",
                                });
                              }
                        
                              let newAccessToken = jwt.sign({ id: refreshToken.user._id }, config.secret, {
                                expiresIn: config.jwtExpiration,
                              });
                        
                              return res.status(200).json({
                                accessToken: newAccessToken,
                                refreshToken: refreshToken.token,
                              });
                            }).catch(err => {
                              return res.status(500).send({ message: err });
                            });
                        };