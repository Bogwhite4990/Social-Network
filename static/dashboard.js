
        let offset = {{ photos | length }};
    const limit = 5;  // Adjust the limit as needed

    function loadMorePhotos() {
        // AJAX request to fetch the next set of photos
        $.ajax({
            type: "POST",
            url: "{{ url_for('dashboard') }}",
            headers: {"X-Requested-With": "XMLHttpRequest"},
            data: {offset: offset, limit: limit},
            success: function(response) {
                // Append the new photos to the container
                const photoContainer = $("#photo-container");
                for (const photo of response) {
                    const photoHtml = `
                        <div class="photo">
                            <img src="{{ url_for('static', filename='uploads/') }}${photo.filename}" alt="Photo">
                            <p>Uploaded by: ${photo.user.username}</p>
                        </div>
                    `;
                    photoContainer.append(photoHtml);
                }

                // Update the offset for the next request
                offset += response.length;

                // Check if there are more photos to load
                if (response.length < limit) {
                    $("#load-more-btn").hide();
                }
            },
            error: function(error) {
                console.error("Error loading more photos:", error);
            }
        });
    }

    // Attach the loadMorePhotos function to the "Load More" button click event
    $("#load-more-btn").on("click", loadMorePhotos);

    // Trigger initial loading of photos
    loadMorePhotos();

   // Function to toggle the notification dropdown
function toggleNotificationDropdown() {
    const notificationPopup = document.getElementById('notification-popup');
    if (notificationPopup.style.display === 'block') {
        notificationPopup.style.display = 'none';
    } else {
        notificationPopup.style.display = 'block';
        // You can load and display notifications here dynamically
    }
}

// Add a click event listener to the bell icon
const notificationIcon = document.getElementById('notification-icon');
notificationIcon.addEventListener('click', toggleNotificationDropdown);


    // JavaScript to handle the game dropdown
document.addEventListener("DOMContentLoaded", function() {
    const gameIcon = document.getElementById("game-icon");
    const gameDropdown = document.querySelector(".game-dropdown-content");

    // Toggle the dropdown when clicking on the game icon
    gameIcon.addEventListener("click", function(event) {
        event.stopPropagation(); // Prevent the click event from propagating to document

        // Toggle the visibility of the dropdown content
        if (gameDropdown.style.display === "block") {
            gameDropdown.style.display = "none";
        } else {
            gameDropdown.style.display = "block";
        }
    });

    // Close the dropdown when clicking outside of it
    document.addEventListener("click", function(event) {
        if (gameDropdown.style.display === "block" && !event.target.closest(".game-dropdown")) {
            gameDropdown.style.display = "none";
        }
    });
});


    function convertUtcToLocal(utcTimestamp) {
        const utcDate = new Date(utcTimestamp);
        const localDate = new Date(utcDate.toLocaleString("en-US", { timeZone: "Europe/Bucharest" })); // Replace "Europe/Bucharest" with the correct user's time zone
        return localDate;
    }

    function updateStatus() {
        $('.user-status').each(function() {
            const lastSeenUtcTimestamp = $(this).data('last-seen'); // Get the UTC timestamp from the data attribute
            const lastSeenLocalTime = convertUtcToLocal(lastSeenUtcTimestamp); // Convert to local time

            // Add 3 hours to the lastSeenLocalTime
            lastSeenLocalTime.setHours(lastSeenLocalTime.getHours() + 3);

            const currentTime = new Date();
            const fiveMinutesAgo = new Date(currentTime - 5 * 60 * 1000); // 5 minutes ago

            if (lastSeenLocalTime >= fiveMinutesAgo) {
                $(this).addClass('online').removeClass('offline').text(' • Online'); // Add Online status
            } else {
                $(this).addClass('offline').removeClass('online').text(' • Offline'); // Add Offline status
            }
        });
    }

    $(document).ready(function() {
        updateStatus();

        // Update user status every minute (you can adjust the interval as needed)
        setInterval(updateStatus, 60000); // 1 minute
    });


        function viewPhoto(photoId) {
        // Construct the URL for the view_photo page with the photoId
        var url = "/photo/" + photoId; // Update the URL pattern as needed

        // Redirect the user to the view_photo page
        window.location.href = url;
    }
    // JavaScript to handle comment submission
    document.querySelectorAll(".comment-form").forEach(form => {
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            const formData = new FormData(form);
            const response = await fetch("/add_comment", {
                method: "POST",
                body: formData,
            });
            if (response.ok) {
                // Reload the page or update the comments display as needed
                window.location.reload();
            }
        });
    });

    // JavaScript to handle comment deletion
    document.querySelectorAll(".delete-comment-button").forEach(button => {
        button.addEventListener("click", async () => {
            const response = await fetch(button.parentElement.action, {
                method: "POST",
            });
            if (response.ok) {
                // Reload the page or update the comments display as needed
                window.location.reload();
            }
        });
    });

const likeButtons = document.querySelectorAll('.like-button');

likeButtons.forEach(button => {
    button.addEventListener('click', async () => {
        const photoId = button.getAttribute('data-photo-id');
        const liked = button.getAttribute('data-liked') === 'true';
        const likeCount = button.nextElementSibling; // Item displaying the number of likes

        // Send an AJAX request to the server to update the like
        const response = await fetch(`/like_photo/${photoId}`, {
            method: 'POST',
        });

        if (response.ok) {
            const data = await response.json();
            // Update the number of likes with the value received from the server
            likeCount.textContent = data.like_count;

            // Change the button emoji according to the current state (liked/unliked)
            if (liked) {
                button.textContent = '💔'; // Change to broken heart emoji
            } else {
                button.textContent = '❤️'; // Change to heart emoji
            }
            button.setAttribute('data-liked', !liked);

            // Create and append falling hearts (or broken hearts)
            for (let i = 0; i < 5; i++) {
                createFallingHeart(button, liked);
            }

            // Store the like state in localStorage
            localStorage.setItem(`like_state_${photoId}`, !liked);
        }
    });

    // Check and set the initial like state from localStorage
    const photoId = button.getAttribute('data-photo-id');
    const likedInStorage = localStorage.getItem(`like_state_${photoId}`);
    if (likedInStorage !== null) {
        button.setAttribute('data-liked', likedInStorage === 'true');
        button.textContent = likedInStorage === 'true' ? '❤️' : '💔';
    }
});


// Function to create and append a falling heart (or broken heart) element
function createFallingHeart(button, liked) {
    const heart = document.createElement('div');
    heart.className = 'heart';

    // Position the heart at the button's position
    const buttonRect = button.getBoundingClientRect();
    heart.style.left = buttonRect.left + 'px';
    heart.style.top = buttonRect.top + 'px';

    // Set the appropriate background image based on liked/unliked
    if (liked) {
        heart.style.backgroundImage = 'url("path/to/broken_heart.png")';
    } else {
        heart.style.backgroundImage = 'url("path/to/heart.png")';
    }

    document.body.appendChild(heart);

    // Remove the heart element after the animation completes
    heart.addEventListener('animationend', () => {
        heart.remove();
    });
}


    // Function to handle image uploads (if needed)
    function handleImageUpload(input) {
        if (input.files && input.files[0]) {
            var formData = new FormData();
            formData.append('photo', input.files[0]);
            fetch("{{ url_for('upload_photo') }}", {
                method: 'POST',
                body: formData
            });
        }
        setTimeout(function () {
            window.location.reload();
        }, 1000);
    }

    // Function to apply the border color from the data attribute
    function applyBorderColor() {
        const uploadedImages = document.querySelectorAll('.uploaded-image');
        uploadedImages.forEach(image => {
            const borderColor = image.getAttribute('data-border-color');
            if (borderColor) {
                image.style.borderColor = borderColor; // Set the border color
            }
        });
    }

    // Function to apply the username color from the data attribute
    function applyUsernameColor() {
        const usernameElements = document.querySelectorAll('.user-profile-link.username-color');
        usernameElements.forEach(usernameElement => {
            const usernameColor = usernameElement.getAttribute('data-username-color');
            if (usernameColor) {
                usernameElement.style.color = usernameColor; // Set the username color
            }
        });
    }

    // Function to open the modal and display the larger image
function openModal(imageSrc) {
    const modal = document.getElementById("imageModal");
    const modalImage = document.getElementById("modalImage");

    modal.style.display = "block";
    modalImage.src = imageSrc;

    // Add an event listener to close the modal if the user clicks on the modal image
    modalImage.addEventListener('click', closeModal);

    // Add an event listener to close the modal if the user clicks outside of it
    document.addEventListener('click', closeModalOutside);
}


    // Function to close the modal
    function closeModal() {
        const modal = document.getElementById("imageModal");
        modal.style.display = "none";

        // Remove the event listener when the modal is closed
        document.removeEventListener('click', closeModalOutside);
    }

    // Function to close the modal if the user clicks outside of it
    function closeModalOutside(event) {
        const modal = document.getElementById("imageModal");
        if (event.target === modal) {
            closeModal();
        }
    }

    // Call these functions when the dashboard page loads
    window.addEventListener('load', () => {
        applyBorderColor();
        applyUsernameColor();
    });

// Function to apply the border width from the data attribute
function applyBorderWidth() {
    const uploadedImages = document.querySelectorAll('.uploaded-image');
    uploadedImages.forEach(image => {
        const borderWidth = image.getAttribute('data-border-width');
        console.log(`Image Border Width: ${borderWidth}`);
        if (borderWidth) {
            // Check if the "2px Border" item has been purchased
            const is2pxBorderPurchased = sessionStorage.getItem('is2pxBorderPurchased');
            if (is2pxBorderPurchased === 'true') {
                // Apply the 2px border width
                image.style.borderWidth = '4px'; // Set it to 4px as you've defined
            } else {
                // Apply the regular border width from the data attribute
                image.style.borderWidth = borderWidth + 'px';
            }
            console.log(`Setting Border Width: ${image.style.borderWidth}`);
        }
    });
}

// Call this function when the dashboard page loads
window.addEventListener('load', () => {
    applyBorderWidth();
});


function showNotifications() {
  // Fetch notifications using AJAX
  fetch('/get_notifications')
    .then((response) => response.json())
    .then((data) => {
      const notificationPopup = document.getElementById('notification-popup');
      notificationPopup.innerHTML = '';

      if (data.length === 0) {
        notificationPopup.innerHTML = 'No new notifications.';
        // Keep the bell icon when there are no notifications
        document.getElementById('notification-icon').textContent = '🔔';
      } else {
        // Sort notifications by type and content for collapsing
        data.sort((a, b) => (a.type + a.content).localeCompare(b.type + b.content));

        // Initialize variables for collapsed notifications
        let currentNotification = null;
        let count = 0;

        // Function to display a notification
        function displayNotification(notification) {
          const notificationItem = document.createElement('div');
          notificationItem.textContent = `${count}x ${notification.content}`;
          notificationPopup.appendChild(notificationItem);
        }

        // Iterate through the sorted notifications
        data.forEach((notification) => {
          if (
            currentNotification === null ||
            notification.type !== currentNotification.type ||
            notification.content !== currentNotification.content
          ) {
            // Display the previous collapsed notification, if any
            if (currentNotification !== null) {
              displayNotification(currentNotification);
            }

            // Start counting a new notification
            currentNotification = { ...notification };
            count = 1;
          } else {
            // Continue counting the current notification
            count++;
          }
        });

        // Display the last collapsed notification, if any
        if (currentNotification !== null) {
          displayNotification(currentNotification);
        }

        // Mark notifications as read and change the icon to the envelope
        data.forEach((notification) => {
          markNotificationAsRead(notification.id);
          document.getElementById('notification-icon').textContent = '📩';
        });
      }
    })
    .catch((error) => console.error('Error fetching notifications:', error));
}



    function markNotificationAsRead(notificationId) {
        // Send a request to mark the notification as read
        fetch(`/mark_notification_as_read/${notificationId}`, { method: 'POST' })
            .catch(error => console.error('Error marking notification as read:', error));
    }
   // Add this code to the existing JavaScript
window.addEventListener('load', function () {
    const notificationPopup = document.getElementById('notification-popup');
    notificationPopup.innerHTML = ''; // Clear notifications on page load/refresh
});

   setInterval(showNotifications, 6000); // Check every 6 seconds for new notifications

       // JavaScript for the bubble effect (put this script after the bubble container)
    function createBubble() {
        const bubbleContainer = document.querySelector(".bubble-container");

        const bubble = document.createElement("div");
        bubble.className = "bubble";

        // Generate random position
        const randomX = Math.random() * (window.innerWidth - 186); // Adjusted for bubble size
        const randomY = Math.random() * (window.innerHeight - 186); // Adjusted for bubble size

        bubble.style.top = randomY + "px";
        bubble.style.left = randomX + "px";

        // Generate a random gradient background color
        const randomColor = getRandomGradientColor();
        bubble.style.background = randomColor;

        // Generate random bubble size (small or large)
        const isSmall = Math.random() < 0.5; // 50% chance of being small
        if (isSmall) {
            bubble.classList.add("small-bubble");
        }

        bubbleContainer.appendChild(bubble);

        // Remove the bubble after animation completes
        bubble.addEventListener("animationiteration", () => {
            bubble.remove();
        });
    }

    // Generate a random gradient background color
    function getRandomGradientColor() {
        const colors = [
            'linear-gradient(45deg, lightpurple, lightblue)',
            'linear-gradient(45deg, fuchsia, lightpink)',
            'linear-gradient(45deg, lavender, lightskyblue)',
            'linear-gradient(45deg, thistle, powderblue)',
            'linear-gradient(45deg, plum, deepskyblue)',
            'linear-gradient(45deg, violet, lightcyan)',
            'linear-gradient(45deg, orchid, azure)',
            'linear-gradient(45deg, mediumorchid, lightsteelblue)',
            'linear-gradient(45deg, hotpink, aliceblue)',
            'linear-gradient(45deg, deeppink, lavenderblush)',
            // Add more gradient colors as needed
        ];
        const randomIndex = Math.floor(Math.random() * colors.length);
        return colors[randomIndex];
    }

    // Create random bubbles at regular intervals
    setInterval(createBubble, 4000); // Adjust the interval as needed

   // Prevent bubble interference with comment input field
const commentInput = document.querySelector("input[name='text']");
commentInput.addEventListener("click", function (event) {
    event.stopPropagation(); // Prevent the click event from reaching the bubbles
});