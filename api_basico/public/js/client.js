async function main() {
    let response = await fetch("http://localhost:3000/api/hello");
    let message = await response.json();
    console.log(message);
    response = await fetch("http://localhost:3000/api/users/2");
    message = await response.json();
    console.log(message);
}
main();