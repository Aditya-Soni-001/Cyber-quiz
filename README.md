# CyberSec Quiz 🛡️

An interactive web-based quiz designed to test and improve your cybersecurity knowledge. Built with **HTML**, **CSS**, and **Vanilla JavaScript**, featuring animated particle effects, neon-themed UI, and categorized questions across multiple domains.

---

## 🚀 Features

- **Multiple Cybersecurity Domains**: Fundamentals, Network Security, Cryptography, Malware & more.  
- **Dynamic Question Bank**: Questions are randomized from `questions.js` for each attempt.  
- **Topic Selection**: Choose a category before starting the quiz.  
- **Question Count Options**: Attempt 10, 20, or all available questions per topic.  
- **Scoring & Feedback**: Immediate feedback with explanations after each answer.  
- **Progress Tracking**: Progress bar and score tracker during the quiz.  
- **Results Screen**: Shows score, evaluation message, and retry option.  
- **Celebration Confetti** 🎉 for a perfect score.  
- **Cyberpunk UI**: Neon green terminal-style theme with animated particle effects.  

---

## 📂 Project Structure

```
├── index.html       # Main entry point  
├── style.css        # Neon cyberpunk styling  
├── script.js        # Quiz logic & particle animation  
├── questions.js     # Question bank with explanations  
├── sample.js        # Placeholder for extending question sets  
```

---

## 🛠️ How to Run

1. Clone or download the repository.  
2. Open `index.html` in your browser.  
3. Start the quiz by selecting a domain and number of questions.  

No server setup required – runs fully in the browser.

---

## 📸 Preview

- **Home Screen**: Cyberpunk intro with glowing shield icon.  
- **Quiz Screen**: Dynamic questions, answers, and explanations.  
- **Results Screen**: Shows performance with motivational messages.  

---

## 🔮 Improvements / Suggestions

1. **Accessibility**:  
   - Add ARIA labels and better keyboard navigation.  
   - Ensure color contrast is accessible for all users.  

2. **Persistence**:  
   - Store scores & progress in `localStorage` for replay value.  
   - Add a leaderboard if multiplayer is desired.  

3. **Mobile Optimization**:  
   - The current grid layout works, but buttons might feel cramped on small screens. Consider a single-column layout on <600px.  

4. **More Interactivity**:  
   - Timer per question or timed quiz mode.  
   - Difficulty levels (easy, medium, hard).  

5. **Expand Question Bank**:  
   - Add more categories like Cloud Security, Forensics, Incident Response.  

6. **Deployment**:  
   - Deploy on GitHub Pages / Netlify for quick sharing.  

---

## 📜 License

This project is open-source under the **MIT License** – free to use, modify, and distribute.  