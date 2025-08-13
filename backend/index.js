require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { GoogleGenerativeAI } = require("@google/generative-ai");
const crypto = require("crypto");

const app = express();
const port = 3001;

app.use(cors);
app.use(express.json());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Successfully connected to MongoDB!"))
  .catch((err) => console.error("Database connection error:", err));


const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: { type: String, required: true },
  username: {
    type: String,
    required: true,
    unique: true,
    default: () => `user_${crypto.randomBytes(12).toString("hex")}`,
  },
});
const User = mongoose.model("User", userSchema);


const recipeSchema = new mongoose.Schema({
  content: { type: String, required: true },
  imageUrl: { type: String },
  nutrition: { type: String }, 
  user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
});
const Recipe = mongoose.model("Recipe", recipeSchema);


const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);


const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null)
    return res.status(401).json({ error: "No token provided." });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token is not valid." });
    req.user = user;
    next();
  });
};

const getTitleFromMarkdown = (markdown) => {
  if (!markdown) return "food";
  const titleLine = markdown.split("\n").find((line) => line.startsWith("# "));
  return titleLine ? titleLine.replace("# ", "").trim() : "delicious food";
};

app.post("/api/signup", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res
        .status(409)
        .json({ error: "An account with this email already exists." });
    }
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();
    res
      .status(201)
      .json({ message: "User created successfully! You can now log in." });
  } catch (error) {
    console.error("Signup Error:", error);
    if (error.code === 11000) {
      return res
        .status(409)
        .json({ error: "An account with this email already exists." });
    }
    res.status(500).json({ error: "Server error during user registration." });
  }
});


app.post("/api/signin", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ error: "Email and password are required." });
    }
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials." });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials." });
    }
    const payload = { id: user._id, email: user.email };
    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ message: "Logged in successfully!", token });
  } catch (error) {
    console.error("Signin Error:", error);
    res.status(500).json({ error: "Server error during login." });
  }
});


app.post("/api/generate-recipe", authenticateToken, async (req, res) => {
  try {
    const { ingredients } = req.body;
    if (!ingredients || ingredients.length === 0)
      return res.status(400).json({ error: "Ingredients are required." });

    const model = genAI.getGenerativeModel({
      model: "gemini-1.5-flash-latest",
    });

    
    const recipePrompt = `You are a creative chef. Generate a delicious recipe using: ${ingredients.join(
      ", "
    )}. Provide a unique name for the dish, ingredients list, and instructions. Structure your response in Markdown, starting with a '# Title'.`;
    const recipeResult = await model.generateContent(recipePrompt);
    const recipeText = recipeResult.response.text();


    const nutritionPrompt = `Analyze the following recipe and provide a brief, estimated nutritional breakdown per serving (Calories, Protein, Carbs, Fat). Format as a simple Markdown list. Recipe:\n\n${recipeText}`;
    const nutritionResult = await model.generateContent(nutritionPrompt);
    const nutritionText = nutritionResult.response.text();


    const recipeTitle = getTitleFromMarkdown(recipeText);
    let imageUrl =
      "https://placehold.co/600x400/2dd4bf/ffffff?text=Delicious+Food"; 
    const unsplashUrl = `https://api.unsplash.com/search/photos?page=1&query=${encodeURIComponent(
      recipeTitle
    )}&client_id=${process.env.UNSPLASH_ACCESS_KEY}&per_page=1`;

    try {
      const imageResponse = await fetch(unsplashUrl);
      const imageData = await imageResponse.json();
      if (imageData.results && imageData.results.length > 0) {
        imageUrl = imageData.results[0].urls.regular;
      }
    } catch (imageError) {
      console.error("Could not fetch image from Unsplash:", imageError);
    }

    res.json({
      recipe: recipeText,
      nutrition: nutritionText,
      imageUrl: imageUrl,
    });
  } catch (error) {
    console.error("Error generating recipe:", error);
    res.status(500).json({ error: "Failed to generate recipe." });
  }
});


app.post("/api/recipes", authenticateToken, async (req, res) => {
  try {
    const { content, nutrition, imageUrl } = req.body; 
    if (!content)
      return res.status(400).json({ error: "Recipe content is required." });

    const newRecipe = new Recipe({
      content,
      nutrition,
      imageUrl,
      user: req.user.id,
    });
    await newRecipe.save();
    res
      .status(201)
      .json({ message: "Recipe saved successfully!", recipe: newRecipe });
  } catch (error) {
    res.status(500).json({ error: "Server error while saving recipe." });
  }
});

app.get("/api/recipes", authenticateToken, async (req, res) => {
  try {
    const recipes = await Recipe.find({ user: req.user.id }).sort({
      createdAt: -1,
    });
    res.json(recipes);
  } catch (error) {
    console.error("Get Recipes Error:", error);
    res.status(500).json({ error: "Server error while fetching recipes." });
  }
});

app.listen(port, () => {
  console.log(`Backend server running at http://localhost:${port}`);
});

app.delete("/api/recipes/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const recipe = await Recipe.findOneAndDelete({
      _id: id,
      user: req.user.id,
    });

    if (!recipe) {
      return res
        .status(404)
        .json({
          error: "Recipe not found or you do not have permission to delete it.",
        });
    }

    res.json({ message: "Recipe deleted successfully." });
  } catch (error) {
    console.error("Delete Recipe Error:", error);
    res.status(500).json({ error: "Server error while deleting recipe." });
  }
});
