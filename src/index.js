//IMPORTING MODULES
import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import fileupload from "express-fileupload";
import cloudinary from "cloudinary";
//dotenv configuration:
dotenv.config();
//cloudinary configuration:

cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
//creating exprtess app:
const app = express();
//Using middlewares:
app.use(cors());
app.use(express.json());
app.use(fileupload({ useTempFiles: true }));
//Connecting to database:
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Succesfully connected to DB"))
  .catch(() => console.log("DB connection got failed!"));
//Creating mongoose userSchema:
const userSchema = new mongoose.Schema(
  {
    userName: {
      type: String,
    },
    email: {
      type: String,
    },
    password: {
      type: String,
    },
    avatarUrl: {
      type: String,
      default: "/img/defaultAvatar.webp",
    },
  },
  { timestamps: true }
);
//Hashing password before saving it ton database:
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});
//creating user model:
const User = mongoose.model("User", userSchema);
//Creating user router:
const userRouter = express.Router();
//Creating sign up route:
userRouter.post("/signup", async (req, res) => {
  const { userName, email, password } = req.body;
  //Checking wether user exist or not.
  const userExist = await User.findOne({ email });
  if (userExist) {
    return res.status(201).json({ msg: "User already exist." });
  }
  //creating a new user:
  try {
    const user = await new User({ userName, email, password });
    //saving the user in mongodb atlas.
    await user.save();

    res.status(201).json({ msg: "Registered Successfully!", user });
  } catch (error) {
    console.log("Server Issues.Failed to create a new account", error);

    res
      .status(500)
      .json({ msg: "Server issues!Failed to create a new account" });
  }
});

//login an user:
userRouter.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  console.log(user);

  if (!user) {
    return res.status(201).json({ msg: "User doesn't exist." });
  }
  //checking the password:
  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(201).json({ msg: "Invalid email or password." });
  }
  try {
    //Creating a jwt token:
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_TOKEN,
      { expiresIn: "10d" }
    );
    //sending this token to front end:

    res.status(201).json({ msg: "Logged in successfully", token });
  } catch (error) {
    res.status(500).json({ msg: "server issues!loggin failed" });
  }
});

//creating logout rout:
userRouter.post("/logout", async (req, res) => {
  try {
    res.status(201).json({ msg: "LoggedOut Successfully!" });
  } catch (error) {
    console.log("Loggout failed", error);
  }
});
//uploading file
userRouter.post("/upload", async (req, res) => {
  const file = req.files.file;
  const { email } = req.body; // Extract email from formData

  try {
    const result = await cloudinary.v2.uploader.upload(file.tempFilePath, {
      folder: "uploads",
    });

    const avatarUrl = result.secure_url;

    const oldUser = await User.findOne({ email });
    if (!oldUser) {
      return res.status(404).json({ msg: "User not found." });
    }

    oldUser.avatarUrl = avatarUrl;
    await oldUser.save();

    res.status(201).json({ msg: "File uploaded successfully", avatarUrl });
  } catch (error) {
    console.log(error);
    res.status(500).json({ msg: "File upload failed" });
  }
});

//Creating the user route:
app.use("/api/user", userRouter);
//creating port:
const port = process.env.PORT || 5000;
//Listening the app:
app.listen(port, () =>
  console.log(`Listening to port number:${port} successfully`)
);
