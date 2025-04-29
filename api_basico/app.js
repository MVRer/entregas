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
    new user(2, "Jane Smith", "jane@gmail.com", [3]),
]


const PORT = 3000;
const app = express();


app.delete("/api/items/remove/:id", (req, res) => {
    for (let i = 0; i < items.length; i++) {
        if (items[i].id == req.params.id) {
            items.splice(i, 1);
            res.status(200).json({ message: "Item removed successfully" });
            return;
        }
    }
    res.status(404).json({ message: "Item not found" });
});

app.use(express.json());

app.use(express.static("./public"));


app.post("/api/users/add/", (req, res) => {
    const users_tmp = req.body;
    //console.log(users_tmp);

    if (!Array.isArray(users_tmp)) {
        res.status(400).json({ message: "Wrong format, must be a list of users from length 1 to infinity",
            format: "json",
            example: {
                name: "Jhon",
                mail: "doe@gmail.com",
                items: "[1,2]"
            }
        });
        return;
    }

    for (let i = 0; i < users_tmp.length; i++) {
        const user_tmp = users_tmp[i];
        //console.log(user_tmp);
        if (!user_tmp.name || !user_tmp.mail || !user_tmp.items){
            res.status(400).json({ message: "Wrong format",
                format: "json",
                example: {
                    name: "Jhon",
                    mail: "doe@gmail.com",
                    items: "[1,2]"
                },
                error_in: "user: " + user_tmp.name
            });
            return;
        }
        for (let j = 0; j < users.length; j++) {
            if (users[j].mail === user_tmp.mail) {
                res.status(400).json({ message: "User with that mail already exists", error: "Error in user: " + user_tmp.name });
                return;
            }
        }
        for (let j = 0; j < user_tmp.items.length; j++) {
            const item_tmp = user_tmp.items[j];
            let found = false;
            for (let k = 0; k < items.length; k++) {
                if (items[k].id === item_tmp) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                res.status(400).json({ message: "Item with that id does not exist", error: "Error in user: " + user_tmp.name + " item: " + item_tmp });
                return;
            }
        }
        const newuser = new user(users.length + 1, user_tmp.name, user_tmp.mail, user_tmp.items);
        users.push(newuser);
    }
    res.status(200).json({ message: "Users added successfully" });
    return;
    
});

app.put("/api/items/update/:id", (req, res) => {
    console.log(req.body);
    const idtomod = req.params.id;
    for (let i = 0; i < items.length; i++) {
        if (items[i].id == idtomod) {
            items[i].name = req.body.name;
            items[i].type = req.body.type;
            items[i].effect = req.body.effect;
            res.status(200).json({ message: "Item updated successfully!" });
            return;

        }
    }
    res.status(404).json({ message: "Item not found!" });
    return;
})


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