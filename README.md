# 🛡️ CyberGuard - Phishing & Spam Detection Web App

A modern, gamified web application for detecting phishing URLs and spam messages using AI-powered machine learning models.

## ✨ Features

- **🔍 Multi-Input Analysis**: Analyze URLs, text messages, or messages containing URLs
- **🤖 AI-Powered Detection**: Uses trained machine learning models for accurate threat detection
- **🎮 Gamified Interface**: Cyber-themed UI with animated risk meters and security badges
- **📊 Real-time Results**: Dynamic risk scoring and detailed analysis breakdown
- **📱 Responsive Design**: Works perfectly on desktop and mobile devices

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Required model files (see Setup section)

### Installation

1. **Clone or download the project files**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Add your model files** to the project root:
   - `phishing_model.pkl` - Phishing URL detection model
   - `vectorizer.pkl` - URL feature vectorizer
   - `spam_classifier.pkl` - Spam text detection model
   - `tfidf_vectorizer.pkl` - Text feature vectorizer

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Open your browser** and navigate to:
   ```
   http://localhost:5000
   ```

## 🎯 How It Works

### Input Types

The app automatically detects and analyzes different types of input:

1. **Pure URL**: `https://example.com`
   - Uses phishing detection model
   - Analyzes URL structure and features

2. **Text Message**: `Win a free laptop by replying YES`
   - Uses spam detection model
   - Analyzes text content and patterns

3. **Mixed Content**: `Click here: https://suspicious-site.com`
   - Runs both models
   - Provides combined risk assessment

### Analysis Results

- **Prediction**: Safe, Phishing, Spam, or Suspicious
- **Risk Score**: 0-100 scale with animated visualization
- **Security Badge**: Gamified achievement system
- **Suggested Actions**: Clear recommendations for users
- **Detailed Breakdown**: Component-wise analysis results

## 🎮 Gamification Features

### Security Badges
- 🛡️ **Cyber Guardian** (0-20% risk)
- 🔒 **Security Expert** (20-40% risk)
- ⚠️ **Risk Aware** (40-60% risk)
- 🚨 **Danger Zone** (60-80% risk)
- 💀 **Critical Threat** (80-100% risk)

### Visual Elements
- Animated risk meter with color-coded progress
- Pulsing cyber-themed icons
- Smooth transitions and hover effects
- Responsive design with mobile optimization

## 📁 Project Structure

```
PHISHING/
├── app.py                 # Flask backend application
├── requirements.txt       # Python dependencies
├── README.md             # This file
├── templates/
│   └── index.html        # Main web interface
├── static/
│   └── style.css         # Cyber-themed styling
├── phishing_model.pkl    # Phishing detection model
├── vectorizer.pkl        # URL feature vectorizer
├── spam_classifier.pkl   # Spam detection model
└── tfidf_vectorizer.pkl  # Text feature vectorizer
```

## 🧪 Sample Test Cases

### Safe Examples
- `https://www.google.com`
- `Just finished the meeting, will send the file soon`
- `Check out this legitimate site: https://github.com`

### Suspicious Examples
- `Click here to verify your account: http://bank-login-now.com`
- `Win a free laptop by replying YES to this message`
- `https://suspicious-site.com – Hey, check this out!`

## 🔧 Configuration

### Model Files
Ensure your `.pkl` model files are compatible with scikit-learn and contain:
- **phishing_model.pkl**: Trained classifier for URL phishing detection
- **vectorizer.pkl**: Feature vectorizer for URL analysis
- **spam_classifier.pkl**: Trained classifier for spam text detection
- **tfidf_vectorizer.pkl**: TF-IDF vectorizer for text analysis

### Customization
- Modify risk thresholds in `app.py`
- Adjust UI colors in `static/style.css`
- Update badge levels and messages in the backend

## 🚨 Troubleshooting

### Common Issues

1. **Models not loading**:
   - Ensure all `.pkl` files are in the project root
   - Check file permissions
   - Verify model compatibility with scikit-learn

2. **Port already in use**:
   - Change port in `app.py`: `app.run(port=5001)`
   - Or kill existing process using port 5000

3. **Dependencies issues**:
   - Update pip: `pip install --upgrade pip`
   - Install in virtual environment: `python -m venv venv`

### Health Check
Visit `http://localhost:5000/health` to check if models are loaded correctly.

## 🔒 Security Notes

- This is a demonstration application
- Models should be trained on comprehensive datasets
- Consider additional security measures for production use
- Regularly update models with new threat patterns

## 🤝 Contributing

Feel free to enhance the application with:
- Additional ML models
- New UI themes
- Extended gamification features
- Performance optimizations

## 📄 License

This project is for educational and demonstration purposes.

---

**Built with ❤️ for Cybersecurity Awareness** 