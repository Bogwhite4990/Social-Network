        var questionElement = document.getElementById("questionText");
        var answerOptionsElement = document.getElementById("answerOptions");
        var feedbackElement = document.getElementById("feedbackText");
        var nextButton = document.getElementById("nextButton");
        var backButton = document.getElementById("backButton");
        var scoreElement = document.getElementById("score");
        var timerElement = document.getElementById("timer"); // Added timer element

        var currentQuestionNumber = 0;
        var correctAnswers = 0;
        var totalQuestions = 10;
        var currentQuestionData = null; // Store the current question data
        var score = 0;
        var timer; // Variable to hold the timer

        // Function to update the timer display
        function updateTimerDisplay(seconds) {
            timerElement.textContent = `Time remaining: ${seconds} seconds`;
        }

        // Function to start the timer for 10 seconds (fixed)
        function startTimer() {
            var seconds = 10;
            updateTimerDisplay(seconds);

            timer = setInterval(function () {
                seconds--;
                updateTimerDisplay(seconds);

                if (seconds <= 0) {
                    clearInterval(timer);
                    finishGame(); // Finish the game if timer runs out
                }
            }, 1000); // Update every second
        }

        // Function to fetch and display a new question
        function fetchNextQuestion() {
            if (currentQuestionNumber >= totalQuestions) {
                finishGame(); // Finish the game if all questions are answered
                return;
            }

            // Reset the timer
            clearInterval(timer);

            // Make an API request to fetch the next question and answer options
            fetch('https://opentdb.com/api.php?amount=1&type=multiple')
                .then(response => response.json())
                .then(data => {
                    currentQuestionData = data; // Store the current question data

                    // Extract question and answer data
                    var question = decodeEntities(data.results[0].question);
                    var correctAnswer = data.results[0].correct_answer;
                    var incorrectAnswers = data.results[0].incorrect_answers.map(decodeEntities);

                    // Display the question
                    questionElement.innerHTML = question;

                    // Display the answer options
                    var optionsHtml = '';
                    var allOptions = incorrectAnswers.concat(correctAnswer);
                    allOptions = shuffleArray(allOptions); // Randomize the options
                    allOptions.forEach(option => {
                        optionsHtml += `
                            <div class="answer">
                                <input type="radio" name="user_answer" value="${option}" id="${option}">
                                <label for="${option}">${option}</label>
                            </div>
                        `;
                    });
                    answerOptionsElement.innerHTML = optionsHtml;

                    // Clear previous feedback
                    feedbackElement.textContent = "";

                    // Enable the Next Question button
                    nextButton.disabled = false;

                    // Start the timer for the current question
                    startTimer();
                })
                .catch(error => {
                    console.error('Error fetching question:', error);
                });
        }

        // Function to decode HTML entities
        function decodeEntities(encodedString) {
            var parser = new DOMParser();
            var dom = parser.parseFromString('<!doctype html><body>' + encodedString, 'text/html');
            return dom.body.textContent;
        }

        // Shuffle function to randomize answer options
        function shuffleArray(array) {
            for (var i = array.length - 1; i > 0; i--) {
                var j = Math.floor(Math.random() * (i + 1));
                [array[i], array[j]] = [array[j], array[i]];
            }
            return array;
        }

        // Function to check the selected answer
        function checkAnswer() {
            var selectedAnswer = document.querySelector('input[name="user_answer"]:checked');
            if (!selectedAnswer) {
                // Deduct 1 point if timer runs out and you haven't answered
                score--;
                scoreElement.textContent = score;
                return; // Don't proceed if no answer is selected
            } else {
                var userAnswerText = selectedAnswer.value;
                var correctAnswerElement = document.querySelector(`label[for="${userAnswerText}"]`);
                var correctAnswerText = correctAnswerElement.textContent;
                var correctAnswer = currentQuestionData.results[0].correct_answer;

                // Display feedback for each answer
                if (userAnswerText === correctAnswer) {
                    feedbackElement.innerHTML = `Correct! The answer "${correctAnswerText}" is correct.`;
                    feedbackElement.style.color = "#4CAF50"; // Green for correct answers
                    correctAnswers++;
                    score++;
                } else {
                    feedbackElement.innerHTML = `Wrong! The correct answer was "${correctAnswer}". You selected "${correctAnswerText}".`;
                    feedbackElement.style.color = "#FF5733"; // Red for incorrect answers
                    score--;
                }
            }

            // Update the score
            scoreElement.textContent = score;

            // Disable radio buttons after selection
            var answerRadios = document.querySelectorAll('input[name="user_answer"]');
            answerRadios.forEach(radio => {
                radio.disabled = true;
            });

            currentQuestionNumber++;

            // Automatically go to the next question after displaying feedback or finish the game
            if (currentQuestionNumber >= totalQuestions) {
                finishGame();
            } else {
                fetchNextQuestion();
            }
        }

        // Function to finish the game
        function finishGame() {
            // Hide answer options and timer
            answerOptionsElement.style.display = "none";
            timerElement.style.display = "none";

            // Clear the feedback text
            feedbackElement.textContent = "";

            // Display "Game Over" message along with the score
            questionElement.textContent = "Game Over - Congratulations! You scored " + score + " points.";
            scoreElement.textContent = score;

            // Display the back button
            nextButton.style.display = "none"; // Hide the Next Question button
        }

        // Fetch the first question when the page loads
        fetchNextQuestion();