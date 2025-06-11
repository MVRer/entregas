"use strict";

function main(){

    const buttonCatalog = document.getElementById("fetch-items");
    buttonCatalog.addEventListener("click", () => fetchItems());
    const itemform = document.getElementById("item-form");
    itemform.addEventListener("submit", (event) => {
        event.preventDefault();
        const formdata = new FormData(itemform)
        console.log(formdata);
        fetchItem(formdata.get("item-id"));
        return false;
    } );

}


async function fetchItems(){
    
    const response = await fetch("http://localhost:4000/api/catalog")
    const data = await response.json();
    const displaylist = document.getElementById("product-list");
    
    data.Catalog.forEach(element => {
        const li = document.createElement("li");
        li.className = "added-items";
        li.textContent = `Item ID: ${element.id}, Item name: ${element.name}`
        displaylist.appendChild(li);
    });
}
async function fetchItem(id){
    const response = await fetch(`http://localhost:4000/api/item/${id}`)
    const data = await response.json();
    const iteminfo = document.getElementById("item-info");
    const name = document.createElement("p")
    name.textContent = "Name of the product: " + data.item.name;
    iteminfo.appendChild(name)
}

main();