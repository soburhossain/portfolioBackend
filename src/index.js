import dotenv from "dotenv";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import cors from "cors";
import express from "express";
import jwt from "jsonwebtoken";
import fileupload from "express-fileupload";
import cloudinary from "cloudinary";

// dotenv configuration:
dotenv.config();

// cloudinary configuration:
cloudinary.v2.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

// creating express app:
const app = express();

// Using middlewares:
app.use(cors());
app.use(express.json());
app.use(fileupload({ useTempFiles: true }));

// Connecting to database:
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Successfully connected to DB"))
  .catch(() => console.log("DB connection failed!"));

// Creating mongoose userSchema:
const userSchema = new mongoose.Schema(
  {
    userName: {
      type: String,
    },
    email: {
      type: String,
      unique: true, // Ensure unique email
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

// Hashing password before saving it to database:
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  try {
    this.password = await bcrypt.hash(this.password, 10);
    next();
  } catch (error) {
    next(error);
  }
});

// Creating user model:
const User = mongoose.model("User", userSchema);

// Creating user router:
const userRouter = express.Router();

// Creating sign up route:
userRouter.post("/signup", async (req, res) => {
  const { userName, email, password } = req.body;
  try {
    // Checking whether user exists or not.
    const userExist = await User.findOne({ email });
    if (userExist) {
      return res.status(201).json({ msg: "User already exists." });
    }
    // Creating a new user:
    const user = new User({ userName, email, password });
    await user.save();
    res.status(201).json({ msg: "Registered successfully!" });
  } catch (error) {
    console.log("Server Issues.", error);
    res.status(500).json({ msg: "Server issues!" });
  }
});

// Login a user:
userRouter.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(201).json({ msg: "User does not exist." });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(201).json({ msg: "Invalid email or password." });
    }
    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.JWT_TOKEN,
      { expiresIn: "10d" }
    );

    res.status(201).json({ msg: "Logged in successfully", token, user });
  } catch (error) {
    console.error("Login failed:", error);
    res.status(500).json({ msg: "Server error." });
  }
});

// Changing user password:
userRouter.post("/changepassword", async (req, res) => {
  try {
    const { currentPassword, newPassword, confirmPassword, email } = req.body;
    if (newPassword !== confirmPassword) {
      return res.status(201).json({ msg: "Passwords do not match!" });
    }
    const user = await User.findOne({ email });

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res.status(201).json({ msg: "Incorrect current password!" });
    }
    //const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    user.password = newPassword;
    await user.save();
    res.status(200).json({ msg: "Password changed successfully!", user });
  } catch (error) {
    console.error("Something went wrong:", error);
    res.status(500).json({ msg: "Server error" });
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

// Creating the user route:
app.use("/api/user", userRouter);

// Creating port:
const port = process.env.PORT || 5000;

// Listening to the app:
app.listen(port, () =>
  console.log(`Listening to port number:${port} successfully`)
);
