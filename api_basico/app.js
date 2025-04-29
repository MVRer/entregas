"use strict";

import express from "express";
import fs from "fs";

class user {
    constructor(id, name, mail, items){
        this.id = id;
        this.name = name;
        this.mail = mail;
        this.items = items;
    }
}

class item {
    constructor(id, name, type, effect){
        this.id = id;
        this.name = name;
        this.type = type;
        this.effect = effect;
    }
}

//Catalog
const items = [
    new item(1, "Sword", "Weapon", "Sharpness"),
    new item(2, "Shield", "Armor", "Defense"),
    new item(3, "Potion", "Consumable", "Healing"),
]
const users = [
    new user(1, "John Doe", "jhon@gmail.com", [1,2]),
    new user(2, "Jane Smith", "jane@gmail.com", [1,2]),
]


const PORT = 3000;
const app = express();



app.use(express.json());
app.use(express.static("./public"));
app.put("/api/users/update/:id", (req, res) => {
    const userId = parseInt(req.params.id);
    for (let i = 0; i < users.length; i++) {
        if (users[i].id === userId) {
            users[i].name = req.body.name;
            users[i].mail = req.body.mail;
            users[i].items = req.body.items;
            res.json({messsage: "User updated successfully", user: users[i]});
            return;
        }
    }
    res.status(404).json({ message: "User not found" });
    return;
    

    
});
app.get("/", (req, response) => {
    fs.readFile("./public/html/index.html", "utf8", (err,data) =>{
        if (err) {
            response.status(500).send("Error reading file");
            return;
        }
        response.send(data);
    })
})
app.get("/api/hello", (req, res) => {
    res.json({ message: "Hello from the server!" });
});
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});