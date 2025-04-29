async function main() {


    let response = await fetch("http://localhost:3000/api/hello");
    let message = await response.json();

    console.log(message);

    response = await fetch("http://localhost:3000/api/items/find/1");
    message = await response.json();
    console.log(message);
    response = await fetch("http://localhost:3000/api/items/remove/1", {
        method: "DELETE"
    });
    message = await response.json();
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

    const item = {
        name: "Pencil",
        type: "Weapon",
        effect: "Sharpness"
    };
    const item2 = {
        name: "rocketlauncher",
        type: "Weapon",
        effect: "Sharpness"
    };
    const itemlist = [item, item2];
    const test_endpoint_2 = await fetch("http://localhost:3000/api/items/add", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(itemlist),
    });
    const data = await test_endpoint_2.json();
    console.log(data);
    const test_endpoint_2_2 = await fetch("http://localhost:3000/api/items");
    const data2 = await test_endpoint_2_2.json();
    console.log(data2);

}
main();