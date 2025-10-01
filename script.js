import { questionSets } from './questions.js';

// --- Particle Animation (Cyber Security Matrix Effect) ---
const canvas = document.getElementById('particle-canvas');
const ctx = canvas.getContext('2d');
canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

let particlesArray;

function launchConfetti() {
  // Simple confetti for a 100% score celebration
  confetti({
    particleCount: 150,
    spread: 70,
    origin: { y: 0.6 }
  });
}


const mouse = {
    x: null,
    y: null,
    radius: (canvas.height / 80) * (canvas.width / 80)
};

window.addEventListener('mousemove', function(event) {
    mouse.x = event.x;
    mouse.y = event.y;
});

class Particle {
    constructor(x, y, directionX, directionY, size) {
        this.x = x;
        this.y = y;
        this.directionX = directionX;
        this.directionY = directionY;
        this.size = size;
    }
    draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2, false);
        // Neon green particles
        ctx.fillStyle = 'rgba(0, 255, 65, 0.8)';
        ctx.fill();
    }
    update() {
        if (this.x > canvas.width || this.x < 0) {
            this.directionX = -this.directionX;
        }
        if (this.y > canvas.height || this.y < 0) {
            this.directionY = -this.directionY;
        }

        let dx = mouse.x - this.x;
        let dy = mouse.y - this.y;
        let distance = Math.sqrt(dx * dx + dy * dy);
        if (distance < mouse.radius) {
            // Repel effect when mouse is near
            let angle = Math.atan2(dy, dx);
            let force = (mouse.radius - distance) / mouse.radius;
            this.x -= Math.cos(angle) * force * 5;
            this.y -= Math.sin(angle) * force * 5;
        }
        
        this.x += this.directionX;
        this.y += this.directionY;
        this.draw();
    }
}

function initParticles() {
    particlesArray = [];
    // Increased particle density
    let numberOfParticles = (canvas.height * canvas.width) / 4500; 
    for (let i = 0; i < numberOfParticles; i++) {
        let size = (Math.random() * 4) + 1; // Slightly smaller max size for density
        let x = (Math.random() * ((innerWidth - size * 2) - (size * 2)) + size * 2);
        let y = (Math.random() * ((innerHeight - size * 2) - (size * 2)) + size * 2);
        let directionX = (Math.random() * 0.4) - 0.2;
        let directionY = (Math.random() * 0.4) - 0.2;

        particlesArray.push(new Particle(x, y, directionX, directionY, size));
    }
}

function animateParticles() {
    requestAnimationFrame(animateParticles);
    ctx.clearRect(0, 0, innerWidth, innerHeight);

    for (let i = 0; i < particlesArray.length; i++) {
        particlesArray[i].update();
    }
    connectParticles();
}

function connectParticles() {
    // Increased connection distance for denser matrix look
    let maxDistanceSquared = (canvas.width / 7) * (canvas.height / 7);

    for (let a = 0; a < particlesArray.length; a++) {
        for (let b = a; b < particlesArray.length; b++) {
            let distanceSquared = ((particlesArray[a].x - particlesArray[b].x) * (particlesArray[a].x - particlesArray[b].x))
                + ((particlesArray[a].y - particlesArray[b].y) * (particlesArray[a].y - particlesArray[b].y));

            if (distanceSquared < maxDistanceSquared) {
                // Fainter lines for more complexity but less distraction
                let opacityValue = 1 - (distanceSquared / maxDistanceSquared);
                
                ctx.strokeStyle = `rgba(0, 255, 65, ${opacityValue * 0.5})`; 
                ctx.lineWidth = 1;
                ctx.beginPath();
                ctx.moveTo(particlesArray[a].x, particlesArray[a].y);
                ctx.lineTo(particlesArray[b].x, particlesArray[b].y);
                ctx.stroke();
            }
        }
    }
}

window.addEventListener('resize',
    function() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        mouse.radius = (canvas.height / 80) * (canvas.width / 80);
        initParticles();
    }
);

initParticles();
animateParticles();

// --- Quiz Logic ---
const homeScreen = document.getElementById('home-screen');
const quizContainer = document.getElementById('quiz-container');
const topicSelectScreen = document.getElementById('topic-select-screen');
const quizScreen = document.getElementById('quiz-screen');
const resultScreen = document.getElementById('result-screen');
const enterQuizBtn = document.getElementById('enter-quiz-btn');
const startQuizBtn = document.getElementById('start-quiz-btn');
const nextBtn = document.getElementById('next-btn');
const restartBtn = document.getElementById('restart-btn');
const topicSelect = document.getElementById('topic-select');
const questionCountSelect = document.getElementById('question-count-select');
const questionElement = document.getElementById('question');
const answersElement = document.getElementById('answers');
const explanationElement = document.getElementById('explanation');
const progressBar = document.getElementById('progress-bar');
const currentScoreElem = document.getElementById('current-score');
const questionNumberElem = document.getElementById('question-number');
const finalScoreElem = document.getElementById('score');
const resultMessageElem = document.getElementById('result-message');
const resultTitle = document.getElementById('result-title');
const resultContent = document.getElementById('result-content');
const resultIconContainer = document.getElementById('result-icon-container');


let questions = [];
let currentIndex = 0;
let score = 0;
let questionLimit = 30;


function loadTopics() {
    topicSelect.innerHTML = '';
    const topics = Object.keys(questionSets);
    topics.forEach(topic => {
        const option = document.createElement('option');
        option.value = topic;
        option.textContent = topic;
        topicSelect.appendChild(option);
    });
    topicSelect.addEventListener('change', updateQuestionCountOptions);
    updateQuestionCountOptions();
}

function updateQuestionCountOptions() {
    const selectedTopic = topicSelect.value;
    const actualCount = questionSets[selectedTopic] ? questionSets[selectedTopic].length : 0;
    
    questionCountSelect.innerHTML = '';
    
    // Add 10 and 20 options, if possible
    if (actualCount >= 10) {
        questionCountSelect.innerHTML += '<option value="10">10 Questions</option>';
    }
    if (actualCount >= 20) {
        questionCountSelect.innerHTML += '<option value="20">20 Questions</option>';
    }

    // Add max questions option (default selection)
    questionCountSelect.innerHTML += `<option value="${actualCount}" selected>All Questions (${actualCount})</option>`;
    
    // Update the limit variable for startQuiz to use
    questionLimit = parseInt(questionCountSelect.value, 10);
}

function startQuiz() {
    const selectedTopic = topicSelect.value;
    questionLimit = parseInt(questionCountSelect.value, 10);
    
    let fullSet = [...questionSets[selectedTopic]];
    // Shuffle the full set
    fullSet.sort(() => Math.random() - 0.5); 
    // Slice to the requested limit
    questions = fullSet.slice(0, questionLimit);

    currentIndex = 0;
    score = 0;
    currentScoreElem.innerText = score;
    
    topicSelectScreen.classList.add('hide');
    quizScreen.classList.remove('hide');
    showQuestion();
}

function showQuestion() {
    resetState();
    const currentQuestion = questions[currentIndex];
    const qNum = currentIndex + 1;
    const totalQ = questions.length;
    
    // Use uppercase for the terminal aesthetic
    questionNumberElem.innerText = `DOMAIN: ${topicSelect.value.toUpperCase()} | QUESTION ${qNum} OF ${totalQ}`;
    questionElement.innerText = currentQuestion.question;
    updateProgress();

    currentQuestion.answers.forEach(answer => {
        const button = document.createElement('button');
        button.innerText = answer.text;
        button.classList.add('answer-btn');
        if (answer.correct) {
            button.dataset.correct = answer.correct;
        }
        button.addEventListener('click', selectAnswer);
        answersElement.appendChild(button);
    });
}

function resetState() {
    nextBtn.classList.add('hide');
    explanationElement.classList.add('hide');
    explanationElement.innerHTML = '';
    while (answersElement.firstChild) {
        answersElement.removeChild(answersElement.firstChild);
    }
}

function selectAnswer(e) {
    const selectedBtn = e.target;
    const isCorrect = selectedBtn.dataset.correct === 'true';

    // Disable all buttons and mark selected
    Array.from(answersElement.children).forEach(button => {
        button.disabled = true;
        button.classList.remove('selected');
    });
    selectedBtn.classList.add('selected'); 

    if (isCorrect) {
        score++;
        currentScoreElem.innerText = score;
        selectedBtn.classList.add('correct');
        selectedBtn.classList.remove('selected');
    } else {
        selectedBtn.classList.add('wrong');
        selectedBtn.classList.remove('selected');
        // Highlight the correct answer
        const correctBtn = Array.from(answersElement.children).find(btn => btn.dataset.correct === 'true');
        if (correctBtn) {
            correctBtn.classList.add('correct');
        }
    }

    // Show explanation with terminal prompt style
    explanationElement.innerHTML = `<strong>> EXPLANATION:</strong> ${questions[currentIndex].explanation}`;
    explanationElement.classList.remove('hide');
    
    nextBtn.classList.remove('hide');
}

function nextQuestion() {
    currentIndex++;
    if (currentIndex < questions.length) {
        showQuestion();
    } else {
        showResult();
    }
}

function updateProgress() {
    // Progress bar shows the completed portion of the quiz
    const percent = (currentIndex / questions.length) * 100;
    progressBar.style.width = `${percent}%`;
}

function showResult() {
    quizScreen.classList.add('hide');
    resultScreen.classList.remove('hide');
    // Ensure progress bar completes
    progressBar.style.width = '100%'; 

    finalScoreElem.innerText = `${score} / ${questions.length}`;

    resultContent.classList.remove('result-high-score', 'result-low-score');

    const percentage = (score / questions.length) * 100;

    if (percentage >= 75) {
        resultContent.classList.add('result-high-score');
        // Icon for high score: Cyber Shield
        resultIconContainer.innerHTML = '<i class="fas fa-user-shield"></i>'; 
        resultTitle.innerText = "ACCESS GRANTED. LEVEL: EXPERT";
        if (percentage === 100) {
            resultMessageElem.innerText = "System Integrity: 100%. Flawless Defense. You are a true Cyber Security Master.";
            launchConfetti();
        } else {
            resultMessageElem.innerText = "System Integrity: HIGH. Excellent performance on this domain. Well done!";
        }
    } else {
        resultContent.classList.add('result-low-score');
        // Icon for low score: Open Lock (Symbolizing a breach or vulnerability)
        resultIconContainer.innerHTML = '<i class="fas fa-lock-open"></i>'; 
        resultTitle.innerText = "ACCESS DENIED. VULNERABILITIES FOUND";
        resultMessageElem.innerText = "System Integrity: LOW. Critical review of this domain is required. Keep studying!";
    }
}

function restartQuiz() {
    resultScreen.classList.add('hide');
    topicSelectScreen.classList.remove('hide');
    progressBar.style.width = '0%'; 
    updateQuestionCountOptions();
}

// Event Listeners
enterQuizBtn.addEventListener('click', () => {
    homeScreen.classList.add('hide');
    quizContainer.classList.remove('hide');
});
startQuizBtn.addEventListener('click', startQuiz);
nextBtn.addEventListener('click', nextQuestion);
restartBtn.addEventListener('click', restartQuiz);

// Initial call to load topics when script runs
loadTopics();