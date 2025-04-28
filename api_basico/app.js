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