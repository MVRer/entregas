"use strict";

import express from "express";

const PORT = 3000;
const app = express();
app.use(express.json());
app.use(express.static("public"));
app.get("/api/hello", (req, res) => {
    res.json({ message: "Hello from the server!" });
});
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});