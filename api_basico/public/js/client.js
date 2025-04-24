async function main() {
    const response = await fetch("http://localhost:3333/api/hello");
    const message = await response.json();
    console.log(message);
}
main();