async function main() {
    let response = await fetch("http://localhost:3000/api/hello");
    let message = await response.json();
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
    console.log(message);
}
main();