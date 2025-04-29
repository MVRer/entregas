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
    new user(1, "John Doe", "jhon@gmail.com", [1, 2]),
    new user(2, "Jane Smith", "jane@gmail.com", [2, 3]),
]


const PORT = 3000;
const app = express();



app.use(express.json());
app.use(express.static("./public"));
app.get("/api/users/:id", (req, res) => {
    const userId = parseInt(req.params.id);

    for (let i = 0; i < users.length; i++) {
        if (users[i].id === userId){
            const user = {
                id: users[i].id,
                name: users[i].name,
                mail: users[i].mail,
                items: [],
            };
            for (let j = 0; j < users[i].items.length; j++) {
                const item_id = users[i].items[j];
                for (let k = 0; k < items.length; k++) {
                    if (items[k].id === item_id) {
                        const item_tmp = {
                            id: items[k].id,
                            name: items[k].name,
                            type: items[k].type,
                            effect: items[k].effect,
                        };
                        user.items = user.items || [];
                        user.items.push(item_tmp);
                    }
                }
            }
            res.json(user);
            return;
        }
        
    
    }
    res.status(404).json({ error: "User not found" });
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