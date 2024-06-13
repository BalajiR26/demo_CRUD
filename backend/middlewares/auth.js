import jwt from "jsonwebtoken";
import User from "../models/UserModel.js"; // Adjust the path as necessary

const auth = async (req, res, next) => {
  try {
    // Check if the request headers contain the authorization key
    const { authorization } = req.headers;
    if (!authorization) {
      return res.status(401).json({ error: "Authorization token not found" });
    }

    // Grab the token from headers (taking the "Bearer " string away)
    const token = authorization.split(" ")[1];

    // Decode and extract the user id from token
    const decoded = jwt.verify(token, process.env.SECRET);
    const { _id } = decoded;

    // Find the user in the database by id and select only _id
    const user = await User.findById(_id).select("_id");

    if (!user) {
      throw new Error("User not found");
    }

    // Save the user in request object
    req.user = user;

    // Proceed to the next function/middleware
    next();
  } catch (error) {
    // Handle any errors that occurred during authentication
    res.status(401).json({ error: error.message });
  }
};

export default auth;
