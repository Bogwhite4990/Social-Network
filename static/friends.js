// Function to add a friend
function addFriend(username) {
    // Send an AJAX request to add the user as a friend
    fetch(`/add_friend/${username}`, {
        method: "POST",
    })
    .then(response => {
        if (response.ok) {
            // Friend added successfully
            // You can handle success here, such as updating the UI
            console.log(`Friend ${username} added successfully.`);

            // Update the Friends section in the UI
            const friendsList = document.querySelector(".friends-section ul");
            const friendElement = document.createElement("li");
            friendElement.textContent = username;
            const removeButton = document.createElement("button");
            removeButton.className = "remove-friend-button";
            removeButton.textContent = "Remove Friend";
            removeButton.onclick = () => removeFriend(username);
            friendElement.appendChild(removeButton);
            friendsList.appendChild(friendElement);
        } else {
            // Handle the case where adding a friend failed
            // You can display an error message or take appropriate action
            console.error(`Failed to add friend ${username}.`);
        }
    })
    .catch(error => {
        // Handle any network or request error
        console.error("Error:", error);
    });
}

// Function to remove a friend
function removeFriend(username) {
    // Send an AJAX request to remove the user as a friend
    fetch(`/remove_friend/${username}`, {
        method: "POST",
    })
    .then(response => {
        if (response.ok) {
            // Friend removed successfully
            // You can handle success here, such as updating the UI
            console.log(`Friend ${username} removed successfully.`);

            // Remove the friend from the friends list in the UI
            const friendsList = document.querySelector(".friends-section ul");
            const friendElements = friendsList.querySelectorAll("li");
            friendElements.forEach(friendElement => {
                if (friendElement.textContent.includes(username)) {
                    friendElement.remove();
                }
            });
        } else {
            // Handle the case where removing a friend failed
            // You can display an error message or take appropriate action
            console.error(`Failed to remove friend ${username}.`);
        }
    })
    .catch(error => {
        // Handle any network or request error
        console.error("Error:", error);
    });
}

// Function to send a chat message
function sendMessage(message, recipient_id) {
    fetch("/send_message", {
        method: "POST",
        body: JSON.stringify({ message: message, recipient_id: recipient_id }),
        headers: {
            "Content-Type": "application/json",
        },
    })
    .then(response => {
        if (response.ok) {
            // Message sent successfully
            // You can update the UI or do something on success
        } else {
            console.error("Failed to send message:", response.statusText);
        }
    })
    .catch(error => {
        console.error("Error:", error);
    });
}

// Function to load and display messages
function loadMessages(recipient_id) {
    // Fetch chat messages from the server based on recipient_id
    fetch(`/get_messages/${recipient_id}`)
        .then(response => response.json())
        .then(data => {
            // Display messages in your chat UI
            // You can update your chat UI here
            console.log(data);

            // Append the messages to the chat-messages div
            const chatMessages = document.getElementById("chat-messages");
            chatMessages.innerHTML = ""; // Clear existing messages

            data.forEach(message => {
                const messageElement = document.createElement("div");
                messageElement.textContent = `${message.sender_id}: ${message.text}`;
                chatMessages.appendChild(messageElement);
            });
        })
        .catch(error => {
            console.error("Error:", error);
        });
}

// Define chatForm, messageInput, and friendList variables
const chatForm = document.getElementById("chat-form");
const messageInput = document.getElementById("message-input");
const friendList = document.getElementById("friend-list");
const currentUserId = 1;

// Handle form submission for sending chat messages
chatForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const message = messageInput.value.trim();
    const recipient = friendList.value;
    if (message !== "") {
        sendMessage(message, recipient);
        messageInput.value = "";
        // Load messages after sending
        loadMessages(recipient);
    }
});

// Handle form submission for searching users
const searchForm = document.getElementById("search-user-section");

searchForm.addEventListener("submit", (e) => {
    e.preventDefault();
    searchUsers();
});

// Function to search for users
function searchUsers() {
    const searchQuery = document.querySelector(".search-user-section input[name='search_query']").value;
    fetch(`/search_users/${searchQuery}`, {
        method: "GET",
    })
    .then(response => response.json())
    .then(data => {
        // Handle the JSON data received from the server
        displaySearchResults(data);
    })
    .catch(error => {
        console.error("Error:", error);
    });
}

// Function to display search results on the page
function displaySearchResults(results) {
    const userListingSection = document.querySelector(".user-listing-section ul");

    // Clear any previous search results
    userListingSection.innerHTML = "";

    if (results.length === 0) {
        userListingSection.innerHTML = "<p>No users found.</p>";
    } else {
        // Create and append HTML elements for each user found
        results.forEach(user => {
            const userElement = document.createElement('li');
            userElement.textContent = user.username;
            const addButton = document.createElement('button');
            addButton.className = 'add-friend-button';
            addButton.textContent = 'Add Friend';
            addButton.onclick = () => addFriend(user.username);
            userElement.appendChild(addButton);
            userListingSection.appendChild(userElement);
        });
    }
}
