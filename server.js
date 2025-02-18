require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors());


mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("MongoDB Connected"))
  .catch((err) => console.error("MongoDB Connection Error:", err));


const UserSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});
const User = mongoose.model("User", UserSchema);

// Task Schema
const TaskSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title: { type: String, required: true },
  description: String,
  completed: { type: Boolean, default: false },
});
const Task = mongoose.model("Task", TaskSchema);


const authenticate = async (req, res, next) => {
  console.log("logging req", req.header("Authorization"));
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ error: "Access denied" });

  try {
    const decoded = jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ error: "Invalid token" });
  }
};

app.get("/", (req, res) => res.send("API is running..."));

app.post("/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/tasks", authenticate, async (req, res) => {
  try {
    const task = new Task({ ...req.body, userId: req.user.userId });
    await task.save();
    res.status(201).json({
      success: true,
      message: "Task created successfully",
      data: task,
    });
  } catch (error) {
    res.status(400).json({ error: "Error creating task" });
  }
});

app.get("/tasks", authenticate, async (req, res) => {
  try {
    const tasks = await Task.find({ userId: req.user.userId });
    if(tasks.length > 0) {
      res.json(tasks);
    }
    else{
      res.json({data:"No tasks found"});
    }
  } catch (error) {
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/tasks/:id", authenticate, async (req, res) => {
  try {
    const task = await Task.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!task) return res.status(404).json({ error: "Task not found" });
    res.json(task);
  } catch (error) {
    res.status(400).json({ error: "Invalid task ID" });
  }
});

app.put("/tasks/:id", authenticate, async (req, res) => {
  try {
    const updatedTask = await Task.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      req.body,
      { new: true }
    );
    if (!updatedTask) return res.status(404).json({ error: "Task not found" });
    res.json(updatedTask);
  } catch (error) {
    res.status(400).json({ error: "Invalid task ID" });
  }
});

app.delete("/tasks/:id", authenticate, async (req, res) => {
  try {
    const deletedTask = await Task.findOneAndDelete(req.params.id);
    if (!deletedTask) return res.status(404).json({ error: "Task not found" });
    res.status(204).send();
  } catch (error) {
    res.status(400).json({ error: "Invalid task ID" });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
