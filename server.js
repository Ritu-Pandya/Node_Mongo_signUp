const express = require("express");
const cors = require("cors");

const app = express();

var corsOptions = {
  origin: "http://localhost:8081"
};

app.use(cors(corsOptions));

// parse requests of content-type - application/json
app.use(express.json());

// parse requests of content-type - application/x-www-form-urlencoded
app.use(express.urlencoded({ extended: true }));

const db = require("./app/models");
const dbConfig= require("./app/config/db.config");
const Role = db.role;

db.mongoose
  .connect(`mongodb://${dbConfig.HOST}:${dbConfig.PORT}/${dbConfig.DB}`, {
    useNewUrlParser: true,
    useUnifiedTopology: true
  })
  .then(() => {
    console.log("Successfully connect to MongoDB.");
    initial();
  })
  .catch(err => {
    console.error("Connection error", err);
    process.exit();
  });

  function initial() {
    Role.estimatedDocumentCount().then( count => {
      if (count === 0) {
        new Role({
          name: "user"
        }).save().then(y=>{
          console.log(y)
        }).catch(y=>{
          console.log(y)
        })
  
        new Role({
          name: "moderator"
        }).save().then(y=>{
          console.log(y)
        }).catch(y=>{
          console.log(y)
        })
  
  
        new Role({
          name: "admin"
        }).save().then(y=>{
          console.log(y)
        }).catch(y=>{
          console.log(y)
        })
      }
    }).catch(y=> {
      console.log("error")
    });
  }

  require('./app/routes/auth.routes')(app)
require('./app/routes/user.routes')(app)
  // simple route
  app.get("/", (req, res) => {
    res.json({ message: "Welcome to My application." });
  });
  
  // set port, listen for requests
  const PORT = process.env.PORT || 8080;
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}.`);
  });