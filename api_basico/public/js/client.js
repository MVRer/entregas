async function main() {


    let response = await fetch("http://localhost:3000/api/hello");
    let message = await response.json();
    console.log({test: "Connection to api", response: message} );


    response = await fetch("http://localhost:3000/api/users/update/2", {
        method: "PUT",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            name: "keloke justin biber",
            mail: "pepe@gmail.com",
            items: [1,2]
        })
    });
    message = await response.json();
    console.log({test: "Update specific user", response: message} );


    response = await fetch("http://localhost:3000/api/users/remove/1", {
          method: "DELETE"
    });
    message = await response.json();
    console.log({test: "Delete specific user", response: message} );



    response = await fetch("http://localhost:3000/api/users/2");
    message = await response.json();
    console.log({test: "get specific user", response: message} );



    


    const users = [
        {
            name: "Jhon",
            mail: "didi@gmail.com",
            items: [1, 2]
        },
        {
            name: "Doe",
            mail: "cocolazo@gmail.com",
            items: [1, 3]
        }
    ]

    // Add users test
    response = await fetch("http://localhost:3000/api/users/add", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(users)
    });
    message = await response.json();
    console.log({test: "Add users", response: message} );

    // Get users test
    response = await fetch("http://localhost:3000/api/users");
    message = await response.json();
    console.log({test: "Get all users", response: message} );




    response = await fetch("http://localhost:3000/api/items/find/1");
    message = await response.json();
    console.log({test: "Get specific item", response: message} );

    response = await fetch("http://localhost:3000/api/items/remove/1", {
        method: "DELETE"
    });
    message = await response.json();
    console.log({test: "Delete specific item", response: message} );


    

    response = await fetch("http://localhost:3000/api/items/update/2", {
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
    console.log({test: "Update specific item", response: message} );


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
    console.log({test: "Add items", response: message} );

    response = await fetch("http://localhost:3000/api/items");
    message = await test_endpoint_2_2.json();
    console.log({test: "Get all items", response: message} );





}
main();