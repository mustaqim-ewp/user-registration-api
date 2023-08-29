const express = require("express");
const app = express();
const port = process.env.PORT || 5000;
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

//Middleware
app.use(cors());
app.use(express.json());
const JWTVerify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res
      .status(401)
      .send({ error: true, message: "Unauthorized access!" });
  }
  const token = authHeader.split(" ")[1];
  jwt.verify(token, process.env.PRIVET_KEY, (err, decoded) => {
    if (err) {
      return res
        .status(401)
        .send({ error: true, message: "Unauthorized access!" });
    }
    req.decodedUser = decoded;
    next();
  });
};

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.znibnea.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    const usersCollection = client.db("mydb").collection("users");

    // app.post("/jwt", (req, res) => {
    //   const user = req.body;
    //   const token = jwt.sign(user, process.env.PRIVET_KEY, { expiresIn: "1d" });
    //   res.send({ token: token });
    // });

    app.post("/register", async (req, res) => {
      try {
        const { firstName, lastName, email, password } = req.body;
        if (!firstName || !lastName || !email || !password) {
          return res.status(400).send({ error: true, message: "Bad request!" });
        }
        bcrypt.hash(password, 10, (err, hashedPassword) => {
          req.body.password = hashedPassword;
        });
        const token = jwt.sign({ email }, process.env.PRIVET_KEY, {
          expiresIn: "1d",
        });
        const user = await usersCollection.findOne({ email: email });
        const userEmail = user?.email;
        if (userEmail === email) {
          return res.send({ message: "This email already exist!" });
        } else {
          const result = await usersCollection.insertOne(req.body);
          if (result.insertedId) {
            res.send({
              userId: result.insertedId.toString(),
              token,
              message: "User registered successfully",
            });
          }
        }
      } catch { 
        res.status(400).send({ error: true, message: "Bad request!" });
      }
    });

    app.post("/login", async (req, res) => {
      const user = await usersCollection.findOne({ email: req.body?.email });
      if (user == null) {
        return res.status(400).send("User not found");
      }
      try {
        if (await bcrypt.compare(req.body.password, user.password)) {
          res.send("Login successful");
        } else {
          res.send("Email or password wrong!");
        }
      } catch {
        res.status(500).send("Error logging in");
      }
    });

    app.get("/users/:id", JWTVerify, async (req, res) => {
      try {
        const userId = req.params.id;
        const email = req.query.email;
        if (!email || email !== req.decodedUser?.email) {
          return res
            .status(403)
            .send({ error: true, message: "Forbidden access!" });
        }
        // const result = await usersCollection.findOne({
        //   _id: new ObjectId(userId),
        // });
        const result = await usersCollection.find().toArray();
        res.send(result);
      } catch {
        res.send({ error: true, message: "Server error!" });
      }
    });

    app.put("/users/:id", JWTVerify, async (req, res) => {
      try {
        const userId = req.params.id;
        const email = req.query.email;
        if (!email || email !== req.decodedUser?.email) {
          return res
            .status(403)
            .send({ error: true, message: "Forbidden access!" });
        }
        const updatedData = {
          $set: {
            firstName: req.body?.firstName,
            lastName: req.body?.lastName,
            age: req.body?.age,
            email: req.body?.email,
            password: req.body?.password,
            isAdmin: req.body?.isAdmin,
          },
        };
        const result = await usersCollection.updateOne(
          {
            _id: new ObjectId(userId),
          },
          updatedData
        );
        if (result.modifiedCount > 0) {
          res.send({
            message: "User details updated",
          });
        }
      } catch {
        res.send({ error: true, message: "Server error!" });
      }
    });

    app.delete("/users/:id", JWTVerify, async (req, res) => {
      try {
        const userId = req.params.id;
        const email = req.query.email;
        if (!email || email !== req.decodedUser?.email) {
          return res
            .status(403)
            .send({ error: true, message: "Forbidden access!" });
        }
        const result = await usersCollection.deleteOne({
          _id: new ObjectId(userId),
        });
        if (result.deletedCount > 0) {
          res.send({
            message: "User account deleted",
          });
        }
      } catch {
        res.send({ error: true, message: "Server error!" });
      }
    });

    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.listen(port, () => {
  console.log(`The server is running on port ${port}`);
});
