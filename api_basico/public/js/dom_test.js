const PORT = 3000;

async function fetchUsers() {
    try {
        const response = await fetch(`http://localhost:${PORT}/api/users`);
        if (!response.ok) {
            displayOutput("fetchUsersResult", "Error fetching users: " + response.status);
            return;
        }
        const users = await response.json();
        displayOutput("fetchUsersResult", `Successfully fetched ${users.length} users`);
        
        const userList = document.getElementById('userList');
        userList.innerHTML = '';
        users.forEach(user => {
            const li = document.createElement('li');
            console.log(user);
            li.textContent = `ID: ${user.id}, Name: ${user.name}, Email: ${user.mail}, Items: ${user.items.map(item => item.id).join(', ')}`;
            userList.appendChild(li);
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        displayOutput("fetchUsersResult", "Error fetching users");
    }
}

async function fetchItems() {
    try {
        const response = await fetch(`http://localhost:${PORT}/api/items`);
        if (!response.ok) {
            displayOutput("fetchItemsResult", "Error fetching items: " + response.status);
            return;
        }
        const items = await response.json();
        displayOutput("fetchItemsResult", `Successfully fetched ${items.length} items`);
        
        const itemList = document.getElementById('itemList');
        itemList.innerHTML = '';
        items.forEach(item => {
            const li = document.createElement('li');
            li.textContent = `ID: ${item.id}, Name: ${item.name}, Type: ${item.type}, Effect: ${item.effect}`;
            itemList.appendChild(li);
        });
    } catch (error) {
        console.error('Error fetching items:', error);
        displayOutput("fetchItemsResult", "Error fetching items");
    }
}

function displayOutput(elementId, output) {
    const outputElement = document.getElementById(elementId);
    outputElement.innerHTML = '';
    if (outputElement.hasAttribute("hidden")) {
        outputElement.attributes.removeNamedItem("hidden");
    }
    const p = document.createElement("p");
    p.textContent = output;
    p.className = "output-message";
    outputElement.appendChild(p);
}

async function fetchUser() {
    try {
        const userId = document.getElementById("userIdInput").value;
        if (!userId) {
            displayOutput("fetchUserResult", "Please enter a User ID");
            return;
        }
        
        const response = await fetch(`http://localhost:${PORT}/api/users/${userId}`);
        if (!response.ok) {
            displayOutput("fetchUserResult", "Error: " + response.status);
            return;
        }
        const user = await response.json();
        if (!user.id) {
            displayOutput("fetchUserResult", "User with ID not found");
            return;
        }
        const output = `ID: ${user.id}, Name: ${user.name}, Email: ${user.mail}`;
        displayOutput("fetchUserResult", output);
    } catch (error) {
        console.error('Error fetching user:', error);
        displayOutput("fetchUserResult", "Error fetching user");
    }
}

async function deleteUser() {
    try {
        const userId = document.getElementById("userIdInput").value;
        if (!userId) {
            displayOutput("deleteUserResult", "Please enter a User ID");
            return;
        }
        
        const response = await fetch(`http://localhost:${PORT}/api/users/remove/${userId}`, {
            method: "DELETE"
        });

        if (response.status == 404) {
            displayOutput("deleteUserResult", "User with ID not found");
            return;
        }

        displayOutput("deleteUserResult", "Deleted user with ID: " + userId);
        fetchUsers();
    } catch (error) {
        console.error('Error deleting user:', error);
        displayOutput("deleteUserResult", "Error deleting user");
    }
}

async function updateUser() {
    try {
        const userId = document.getElementById("updateUserIdInput").value;
        if (!userId) {
            displayOutput("updateUserResult", "Please enter a User ID");
            return;
        }
        
        const userName = document.getElementById("updateUserNameInput").value;
        const userMail = document.getElementById("updateUserMailInput").value;
        const userItemsInput = document.getElementById("updateUserItemsInput").value;
        
        const userItems = userItemsInput.split(',').map(item => parseInt(item.trim())).filter(item => !isNaN(item));
        
        const userData = {
            name: userName,
            mail: userMail,
            items: userItems
        };
        
        const response = await fetch(`http://localhost:${PORT}/api/users/update/${userId}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(userData)
        });
        
        if (!response.ok) {
            displayOutput("updateUserResult", "Error updating user: " + response.status);
            return;
        }
        
        const result = await response.json();
        displayOutput("updateUserResult", "User updated successfully");
        fetchUsers();
    } catch (error) {
        console.error('Error updating user:', error);
        displayOutput("updateUserResult", "Error updating user");
    }
}

async function addUser() {
    try {
        const userName = document.getElementById("addUserNameInput").value;
        const userMail = document.getElementById("addUserMailInput").value;
        const userItemsInput = document.getElementById("addUserItemsInput").value;
        
        const userItems = userItemsInput.split(',').map(item => parseInt(item.trim())).filter(item => !isNaN(item));
        
        const userData = [{
            name: userName,
            mail: userMail,
            items: userItems
        }];
        
        const response = await fetch(`http://localhost:${PORT}/api/users/add`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(userData)
        });
        
        if (!response.ok) {
            displayOutput("addUserResult", "Error adding user: " + response.status);
            return;
        }
        
        const result = await response.json();
        displayOutput("addUserResult", "User added successfully");
        fetchUsers();
        
        // Clear form fields
        document.getElementById("addUserNameInput").value = "";
        document.getElementById("addUserMailInput").value = "";
        document.getElementById("addUserItemsInput").value = "";
    } catch (error) {
        console.error('Error adding user:', error);
        displayOutput("addUserResult", "Error adding user");
    }
}

async function fetchItem() {
    try {
        const itemId = document.getElementById("itemIdInput").value;
        if (!itemId) {
            displayOutput("fetchItemResult", "Please enter an Item ID");
            return;
        }
        
        const response = await fetch(`http://localhost:${PORT}/api/items/find/${itemId}`);
        
        if (!response.ok) {
            displayOutput("fetchItemResult", "Error: " + response.status);
            return;
        }
        
        const item = await response.json();
        if (!item.id) {
            displayOutput("fetchItemResult", "Item with ID not found");
            return;
        }
        
        const output = `ID: ${item.id}, Name: ${item.name}, Type: ${item.type}, Effect: ${item.effect}`;
        displayOutput("fetchItemResult", output);
    } catch (error) {
        console.error('Error fetching item:', error);
        displayOutput("fetchItemResult", "Error fetching item");
    }
}

async function deleteItem() {
    try {
        const itemId = document.getElementById("itemIdInput").value;
        if (!itemId) {
            displayOutput("deleteItemResult", "Please enter an Item ID");
            return;
        }
        
        const response = await fetch(`http://localhost:${PORT}/api/items/remove/${itemId}`, {
            method: "DELETE"
        });

        if (response.status == 404) {
            displayOutput("deleteItemResult", "Item with ID not found");
            return;
        }

        displayOutput("deleteItemResult", "Deleted item with ID: " + itemId);
        fetchItems();
    } catch (error) {
        console.error('Error deleting item:', error);
        displayOutput("deleteItemResult", "Error deleting item");
    }
}

async function updateItem() {
    try {
        const itemId = document.getElementById("updateItemIdInput").value;
        if (!itemId) {
            displayOutput("updateItemResult", "Please enter an Item ID");
            return;
        }
        
        const itemName = document.getElementById("updateItemNameInput").value;
        const itemType = document.getElementById("updateItemTypeInput").value;
        const itemEffect = document.getElementById("updateItemEffectInput").value;
        
        const itemData = {
            name: itemName,
            type: itemType,
            effect: itemEffect
        };
        
        const response = await fetch(`http://localhost:${PORT}/api/items/update/${itemId}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(itemData)
        });
        
        if (!response.ok) {
            displayOutput("updateItemResult", "Error updating item: " + response.status);
            return;
        }
        
        displayOutput("updateItemResult", "Item updated successfully");
        fetchItems();
    } catch (error) {
        console.error('Error updating item:', error);
        displayOutput("updateItemResult", "Error updating item");
    }
}

async function addItem() {
    try {
        const itemName = document.getElementById("addItemNameInput").value;
        const itemType = document.getElementById("addItemTypeInput").value;
        const itemEffect = document.getElementById("addItemEffectInput").value;
        
        const itemData = [{
            name: itemName,
            type: itemType,
            effect: itemEffect
        }];
        
        const response = await fetch(`http://localhost:${PORT}/api/items/add`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(itemData)
        });
        
        if (!response.ok) {
            displayOutput("addItemResult", "Error adding item: " + response.status);
            return;
        }
        
        displayOutput("addItemResult", "Item added successfully");
        fetchItems();
        
        // Clear form fields
        document.getElementById("addItemNameInput").value = "";
        document.getElementById("addItemTypeInput").value = "";
        document.getElementById("addItemEffectInput").value = "";
    } catch (error) {
        console.error('Error adding item:', error);
        displayOutput("addItemResult", "Error adding item");
    }
}

async function main() {
    // Users section event listeners
    document.getElementById("fetchUsersButton").addEventListener('click', fetchUsers);
    document.getElementById("fetchUserButton").addEventListener('click', fetchUser);
    document.getElementById("deleteUserButton").addEventListener('click', deleteUser);
    document.getElementById("updateUserButton").addEventListener('click', updateUser);
    document.getElementById("addUserButton").addEventListener('click', addUser);
    
    // Items section event listeners
    document.getElementById("fetchItemsButton").addEventListener('click', fetchItems);
    document.getElementById("fetchItemButton").addEventListener('click', fetchItem);
    document.getElementById("deleteItemButton").addEventListener('click', deleteItem);
    document.getElementById("updateItemButton").addEventListener('click', updateItem);
    document.getElementById("addItemButton").addEventListener('click', addItem);
}

main();