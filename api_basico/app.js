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
    new user(1, "John Doe", "jhon@gmail.com", [items[0], items[1]]),
    new user(2, "Jane Smith", "jane@gmail.com", [items[1], items[2]]),
]


const PORT = 3000;
const app = express();


app.use(express.json());

app.use(express.static("./public"));
app.get("/", (req, response) => {
    fs.readFile("./public/html/index.html", "utf8", (err,data) =>{
        if (err) {
            response.status(500).send("Error reading file");
            return;
        }
        response.send(data);
    })
})
// ITEM API
app.get("/api/items", (req, res) => {
    res.json(items);
    
});


app.post("/api/items/add/", (req, res) => {
    const items_tmp = req.body;
    console.log(items_tmp);

    if (!Array.isArray(items_tmp)) {
        res.status(400).json({ message: "Wrong format, must be a list of items",
            format: "json",
            example: {
                name: "Sword",
                type: "Weapon",
                effect: "Sharpness"
            }
        });
        return;
    }

    for (let i = 0; i < items_tmp.length; i++) {
        const item_tmp = items_tmp[i];
        console.log(item_tmp);
        if (!item_tmp.name || !item_tmp.type || !item_tmp.effect){
            res.status(400).json({ message: "Wrong format",
                format: "json",
                example: {
                    name: "Sword",
                    type: "Weapon",
                    effect: "Sharpness"
                }
            });
            return;
        }
        for (let j = 0; j < items.length; j++) {
            if (items[j].name === item_tmp.name) {
                res.status(400).json({ message: "Item already exists", error: "Error in item: " + item_tmp.name });
                return;
            }

            
        }
        const newItem = new item(items.length + 1, item_tmp.name, item_tmp.type, item_tmp.effect);
        items.push(newItem);
    }
    res.status(200).json({ message: "Items added successfully" });
    return;
    
});
app.get("/api/hello", (req, res) => {
    res.json({ message: "Hello from the server!" });
});
app.get("/api/items/find/:id", (req, res) => {
    const id = parseInt(req.params.id);
    const item = items.find(i => i.id === id);
    if (!item) {
        return res.status(404).json({ error: "Item not found" });
    }
    res.json(item);
});
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});