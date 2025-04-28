async function main() {
    let response = await fetch("http://localhost:3000/api/hello");
    let message = await response.json();
    console.log(message);
    response = await fetch("http://localhost:3000/api/items/update/1", {
        method: "PUT",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            name: "Excalibur",
            type: "Legendary Sword",
            effect: "Increased damage"
        })
    });
    message = await response.json();
    console.log(message);
}
main();