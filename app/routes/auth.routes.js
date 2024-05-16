const verifySignUp  = require("../middlewares/verifySignup");
const controller = require("../controller/auth.controller");

module.exports = function(app) {

    app.post(
        "/api/auth/signup",
        [
          verifySignUp.checkDuplicateUsernameOrEmail,
         
        ],
        controller.signup
      );

      app.post("/api/auth/signIn",controller.signin)
      app.post("/api/auth/refreshtoken",controller.refreshToken)


}