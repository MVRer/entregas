async function main() {
    let response = await fetch("http://localhost:3000/api/hello");
    let message = await response.json();
    console.log(message);
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


    response = await fetch("http://localhost:3000/api/users/add", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(users)
    });
    message = await response.json();
    console.log(message);
}
main();