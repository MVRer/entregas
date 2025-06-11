import express from 'express';
import fs from 'fs';

const PORT = 4000;
const app = express();
app.use(express.json());
app.use(express.static("./public"))
app.listen(PORT, () => {

});
class toys {
    constructor(id, name) {
        this.id = id;
        this.name = name;
    }
}
class catalog {
    constructor(toys){
        this.cataloglist = toys;
    }
}
const toyslist = [new toys(1, "Omnitrix"), new toys(2, "Nintendo"), new toys(3, "Powerranger")];
const cat = new catalog(toyslist);

app.get("/api/hi", (req, res) => {
    res.json({Salutation: "Hello from server"})
    return;
});

app.get("/api/catalog", (req, res) => {
    res.json({Catalog: cat.cataloglist})
});
app.get("/api/item/:id", (req, res) => {
    const id = req.params.id;
    const item = cat.cataloglist[id];
    if (!item) {
        res.status(404).json({error: "Item not found"})
    }
    res.json({item: item})
}); 







