from flask import Flask, render_template, request, jsonify
import pickle
import re
import numpy as np
from urllib.parse import urlparse
import os
import sys
import pytesseract
from PIL import Image
import cv2
import uuid
from werkzeug.utils import secure_filename
import base64
from io import BytesIO
import json
from datetime import datetime

app = Flask(__name__)

# Configuration
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff'}

# Global variables for models
phishing_model = None
vectorizer = None
spam_classifier = None
tfidf_vectorizer = None

# AI Chat Assistant Knowledge Base
CHAT_KNOWLEDGE_BASE = {
    "phishing": {
        "keywords": ["phishing", "fake", "suspicious", "bank", "login", "password", "verify", "account"],
        "responses": [
            "🚨 **Phishing Alert!** This appears to be a phishing attempt. Never click on suspicious links or provide personal information.",
            "⚠️ **Warning:** This looks like a phishing scam. Legitimate companies won't ask for sensitive information via email or text.",
            "🔒 **Security Tip:** Always verify the sender's email address and check for spelling errors in URLs."
        ],
        "actions": [
            "Delete the message immediately",
            "Report it to your email provider",
            "Never click on any links",
            "Enable two-factor authentication on your accounts"
        ]
    },
    "spam": {
        "keywords": ["free", "win", "prize", "lottery", "urgent", "limited time", "exclusive offer"],
        "responses": [
            "📧 **Spam Detected!** This is likely spam. Be cautious of offers that seem too good to be true.",
            "🎯 **Spam Alert:** This message contains typical spam characteristics. Don't respond or click any links.",
            "💡 **Tip:** If it sounds too good to be true, it probably is!"
        ],
        "actions": [
            "Mark as spam in your email",
            "Don't reply to the message",
            "Block the sender",
            "Report to your email provider"
        ]
    },
    "safe": {
        "keywords": ["meeting", "file", "document", "schedule", "work", "project"],
        "responses": [
            "✅ **Safe Content:** This appears to be legitimate communication.",
            "🛡️ **Security Check Passed:** This message looks safe to proceed with.",
            "👍 **Good to go:** This content doesn't show any obvious threats."
        ],
        "actions": [
            "Proceed with normal caution",
            "Verify sender if unsure",
            "Keep your security software updated"
        ]
    },
    "general": {
        "tips": [
            "Always check the sender's email address carefully",
            "Look for spelling and grammar errors",
            "Hover over links before clicking",
            "Never share passwords or personal information",
            "Use strong, unique passwords for each account",
            "Enable two-factor authentication",
            "Keep your software and apps updated",
            "Be suspicious of urgent or threatening messages"
        ],
        "faq": {
            "what_is_phishing": "Phishing is a cyber attack where criminals pretend to be legitimate organizations to steal your personal information.",
            "how_to_spot_phishing": "Look for urgent language, suspicious links, poor grammar, and requests for personal information.",
            "what_to_do_if_clicked": "Change your passwords immediately, monitor your accounts, and report the incident.",
            "is_it_safe": "When in doubt, don't click! It's better to be safe than sorry."
        }
    }
}

def get_ai_assistant_response(user_message, analysis_result=None, context=None):
    """Generate AI assistant response based on user message and context"""
    
    user_message_lower = user_message.lower()
    response = {
        "message": "",
        "suggestions": [],
        "tips": [],
        "actions": []
    }
    
    # Check for specific questions
    if any(word in user_message_lower for word in ["what", "how", "why", "explain", "help"]):
        if "phishing" in user_message_lower:
            response["message"] = "🔍 **What is Phishing?**\n\nPhishing is a cyber attack where criminals create fake websites or emails that look legitimate to steal your personal information like passwords, credit card numbers, or social security numbers.\n\n**Common signs:**\n• Urgent language ('Act now!') \n• Suspicious links \n• Poor grammar \n• Requests for personal info"
            response["suggestions"] = ["Learn more about phishing", "See examples", "Get security tips"]
            
        elif "spam" in user_message_lower:
            response["message"] = "📧 **What is Spam?**\n\nSpam refers to unwanted, unsolicited messages sent in bulk. While annoying, spam can also be dangerous if it contains malicious links or attachments.\n\n**Spam characteristics:**\n• Too-good-to-be-true offers \n• Urgent calls to action \n• Poor grammar \n• Suspicious attachments"
            response["suggestions"] = ["How to block spam", "Report spam", "Security best practices"]
            
        elif "safe" in user_message_lower or "legitimate" in user_message_lower:
            response["message"] = "✅ **How to Verify if Something is Safe:**\n\n1. **Check the sender** - Verify the email address or phone number\n2. **Look for red flags** - Urgency, threats, or unusual requests\n3. **Hover over links** - Check the actual URL before clicking\n4. **Trust your instincts** - If it feels wrong, it probably is\n5. **Use security tools** - Like this CyberGuard app! 🛡️"
            response["suggestions"] = ["Security checklist", "Red flags to watch for", "Safe browsing tips"]
            
        else:
            response["message"] = "🤖 **CyberGuard AI Assistant**\n\nI'm here to help you stay safe online! I can:\n\n• Explain cybersecurity concepts\n• Help you understand analysis results\n• Provide security tips and best practices\n• Answer questions about phishing and spam\n\nWhat would you like to know about?"
            response["suggestions"] = ["What is phishing?", "How to stay safe online", "Security tips", "Report suspicious content"]
    
    # Context-aware responses based on analysis results
    elif analysis_result:
        prediction = analysis_result.get('final_prediction', '').lower()
        risk_score = analysis_result.get('combined_risk', 0)
        
        if prediction == 'phishing':
            response["message"] = "🚨 **High Risk - Phishing Detected!**\n\nThis content shows strong signs of being a phishing attempt. Here's what you should know:\n\n**Why it's dangerous:**\n• Designed to steal your personal information\n• May lead to identity theft or financial loss\n• Can compromise your accounts\n\n**Immediate actions:**\n• Do NOT click any links\n• Do NOT provide any information\n• Delete the message\n• Report it to authorities"
            response["actions"] = CHAT_KNOWLEDGE_BASE["phishing"]["actions"]
            response["tips"] = ["Enable two-factor authentication", "Use a password manager", "Keep software updated"]
            
        elif prediction == 'spam':
            response["message"] = "📧 **Spam Detected!**\n\nThis message contains characteristics typical of spam. While not always dangerous, spam can:\n\n• Waste your time\n• Contain malicious links\n• Lead to scams\n• Clutter your inbox\n\n**Recommended actions:**\n• Mark as spam\n• Don't reply\n• Block the sender"
            response["actions"] = CHAT_KNOWLEDGE_BASE["spam"]["actions"]
            response["tips"] = ["Set up spam filters", "Be cautious of offers", "Report suspicious messages"]
            
        elif prediction == 'safe':
            response["message"] = "✅ **Safe Content Detected!**\n\nThis appears to be legitimate communication. However, always remain vigilant:\n\n**Good practices:**\n• Verify the sender if unsure\n• Check links before clicking\n• Keep your guard up\n• Report anything suspicious"
            response["actions"] = CHAT_KNOWLEDGE_BASE["safe"]["actions"]
            response["tips"] = ["Stay informed about threats", "Use security tools", "Trust your instincts"]
            
        else:
            response["message"] = "⚠️ **Suspicious Content**\n\nThis content shows some concerning signs. While not clearly malicious, it's better to be cautious.\n\n**Recommendations:**\n• Verify the source\n• Don't click suspicious links\n• Contact the sender directly if needed\n• Report if you're unsure"
            response["tips"] = ["When in doubt, don't click", "Verify before trusting", "Use security tools"]
    
    # General security tips
    elif any(word in user_message_lower for word in ["tip", "advice", "protect", "secure"]):
        tips = CHAT_KNOWLEDGE_BASE["general"]["tips"]
        selected_tips = np.random.choice(tips, min(3, len(tips)), replace=False)
        
        response["message"] = "🛡️ **Security Tips for You:**\n\n" + "\n".join([f"• {tip}" for tip in selected_tips])
        response["suggestions"] = ["More security tips", "Learn about threats", "Get help"]
        
    # Default response
    else:
        response["message"] = "🤖 **Hello! I'm your CyberGuard AI Assistant.**\n\nI'm here to help you stay safe online! You can ask me about:\n\n• **Phishing** - How to spot fake emails and websites\n• **Spam** - Identifying unwanted messages\n• **Security tips** - Best practices for staying safe\n• **Analysis results** - Understanding what I found\n\nJust type your question or use the quick suggestions below!"
        response["suggestions"] = ["What is phishing?", "Security tips", "How to stay safe", "Help me understand results"]
    
    return response

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_image(image_path):
    """Extract text from image using OCR"""
    try:
        # Read image using OpenCV
        image = cv2.imread(image_path)
        if image is None:
            return None, "Failed to read image"
        
        # Convert to RGB (OpenCV uses BGR)
        image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        
        # Preprocess image for better OCR
        # Convert to grayscale
        gray = cv2.cvtColor(image_rgb, cv2.COLOR_RGB2GRAY)
        
        # Apply thresholding to get black text on white background
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        
        # Extract text using pytesseract
        text = pytesseract.image_to_string(thresh, config='--psm 6')
        
        # Clean up the extracted text
        text = text.strip()
        
        if not text:
            # Try with different PSM mode if no text found
            text = pytesseract.image_to_string(image_rgb, config='--psm 3')
            text = text.strip()
        
        return text, None
    except Exception as e:
        return None, f"OCR Error: {str(e)}"

def load_models():
    """Load all the trained models and vectorizers"""
    global phishing_model, vectorizer, spam_classifier, tfidf_vectorizer
    
    try:
        # Load phishing detection models
        print("Loading phishing_model.pkl...")
        with open('phishing_model.pkl', 'rb') as f:
            phishing_model = pickle.load(f)
        print("✅ phishing_model.pkl loaded successfully")
        
        print("Loading vectorizer.pkl...")
        with open('vectorizer.pkl', 'rb') as f:
            vectorizer = pickle.load(f)
        print("✅ vectorizer.pkl loaded successfully")
        
        # Load spam detection models
        print("Loading spam_classifier.pkl...")
        with open('spam_classifier.pkl', 'rb') as f:
            spam_classifier = pickle.load(f)
        print("✅ spam_classifier.pkl loaded successfully")
        
        print("Loading tfidf_vectorizer.pkl...")
        with open('tfidf_vectorizer.pkl', 'rb') as f:
            tfidf_vectorizer = pickle.load(f)
        print("✅ tfidf_vectorizer.pkl loaded successfully")
            
        print("✅ All models loaded successfully!")
        return True
    except FileNotFoundError as e:
        print(f"❌ Model file not found: {e}")
        return False
    except Exception as e:
        print(f"❌ Error loading models: {e}")
        print(f"Error type: {type(e).__name__}")
        print(f"Python version: {sys.version}")
        return False

def extract_urls(text):
    """Extract URLs from text using regex"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text)

def is_url(text):
    """Check if input is a URL"""
    try:
        result = urlparse(text)
        return all([result.scheme, result.netloc])
    except:
        return False

def contains_url(text):
    """Check if text contains URLs"""
    return len(extract_urls(text)) > 0

def get_risk_score(prediction, confidence):
    """Convert prediction and confidence to risk score (0-100)"""
    if prediction == 1:  # Malicious/Spam
        return min(100, int(confidence * 100))
    else:  # Safe
        return max(0, int((1 - confidence) * 100))

def get_suggested_action(prediction, risk_score):
    """Get suggested action based on prediction and risk score"""
    if prediction == 1:  # Malicious/Spam
        if risk_score > 80:
            return "🚨 HIGH RISK: Avoid this completely!"
        elif risk_score > 60:
            return "⚠️ Moderate risk: Proceed with caution"
        else:
            return "🤔 Suspicious: Better to avoid"
    else:  # Safe
        if risk_score < 20:
            return "✅ Safe to proceed"
        else:
            return "⚠️ Low risk but stay vigilant"

def get_badge_level(risk_score):
    """Get gamified badge level based on risk score"""
    if risk_score < 20:
        return "🛡️ Cyber Guardian", "excellent"
    elif risk_score < 40:
        return "🔒 Security Expert", "good"
    elif risk_score < 60:
        return "⚠️ Risk Aware", "warning"
    elif risk_score < 80:
        return "🚨 Danger Zone", "danger"
    else:
        return "💀 Critical Threat", "critical"

def mock_analysis(user_input):
    """Mock analysis for testing when models are not available"""
    is_url_input = is_url(user_input)
    has_urls = contains_url(user_input)
    
    # Simple mock logic for demonstration
    if is_url_input:
        if 'suspicious' in user_input.lower() or 'fake' in user_input.lower():
            risk_score = 85
            prediction = 'Phishing'
        else:
            risk_score = 15
            prediction = 'Safe'
    elif has_urls:
        if 'suspicious' in user_input.lower() or 'bank-login' in user_input.lower():
            risk_score = 75
            prediction = 'Phishing'
        else:
            risk_score = 25
            prediction = 'Safe'
    else:
        if 'free' in user_input.lower() and 'laptop' in user_input.lower():
            risk_score = 90
            prediction = 'Spam'
        elif 'meeting' in user_input.lower() or 'file' in user_input.lower():
            risk_score = 10
            prediction = 'Safe'
        else:
            risk_score = 50
            prediction = 'Suspicious'
    
    return {
        'input': user_input,
        'analysis_type': ['URL'] if is_url_input else (['URL', 'Text'] if has_urls else ['Text']),
        'predictions': {'url': 1 if risk_score > 60 else 0} if is_url_input or has_urls else {'text': 1 if risk_score > 60 else 0},
        'risk_scores': {'url': risk_score} if is_url_input or has_urls else {'text': risk_score},
        'combined_risk': risk_score,
        'final_prediction': prediction,
        'suggested_action': get_suggested_action(1 if risk_score > 60 else 0, risk_score),
        'badge': get_badge_level(risk_score)[0],
        'badge_class': get_badge_level(risk_score)[1]
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    """AI Chat Assistant endpoint"""
    try:
        data = request.get_json()
        user_message = data.get('message', '').strip()
        analysis_result = data.get('analysis_result', None)
        context = data.get('context', None)
        
        if not user_message:
            return jsonify({'error': 'Please provide a message'}), 400
        
        # Generate AI response
        ai_response = get_ai_assistant_response(user_message, analysis_result, context)
        
        # Add timestamp
        ai_response['timestamp'] = datetime.now().strftime('%H:%M')
        
        return jsonify(ai_response)
        
    except Exception as e:
        return jsonify({'error': f'Chat failed: {str(e)}'}), 500

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.get_json()
        user_input = data.get('input', '').strip()
        
        if not user_input:
            return jsonify({
                'error': 'Please provide some input to analyze'
            }), 400
        
        # Check if models are loaded
        if not all([phishing_model, vectorizer, spam_classifier, tfidf_vectorizer]):
            print("⚠️ Models not loaded, using mock analysis for demonstration")
            results = mock_analysis(user_input)
            results['warning'] = 'Using mock analysis - models not loaded'
            return jsonify(results)
        
        results = {
            'input': user_input,
            'analysis_type': [],
            'predictions': {},
            'risk_scores': {},
            'combined_risk': 0,
            'final_prediction': 'Safe',
            'suggested_action': '',
            'badge': '',
            'badge_class': ''
        }
        
        # Determine input type and run appropriate models
        is_url_input = is_url(user_input)
        has_urls = contains_url(user_input)
        
        if is_url_input:
            # Pure URL input - use phishing model
            results['analysis_type'].append('URL')
            url_features = vectorizer.transform([user_input])
            url_prediction = phishing_model.predict(url_features)[0]
            url_confidence = max(phishing_model.predict_proba(url_features)[0])
            
            results['predictions']['url'] = int(url_prediction)
            results['risk_scores']['url'] = get_risk_score(url_prediction, url_confidence)
            
        elif has_urls:
            # Text with URLs - run both models
            results['analysis_type'].extend(['URL', 'Text'])
            
            # Extract first URL for phishing analysis
            urls = extract_urls(user_input)
            url_features = vectorizer.transform([urls[0]])
            url_prediction = phishing_model.predict(url_features)[0]
            url_confidence = max(phishing_model.predict_proba(url_features)[0])
            
            # Text analysis for spam
            text_features = tfidf_vectorizer.transform([user_input])
            text_prediction = spam_classifier.predict(text_features)[0]
            text_confidence = max(spam_classifier.predict_proba(text_features)[0])
            
            results['predictions']['url'] = int(url_prediction)
            results['predictions']['text'] = int(text_prediction)
            results['risk_scores']['url'] = get_risk_score(url_prediction, url_confidence)
            results['risk_scores']['text'] = get_risk_score(text_prediction, text_confidence)
            
        else:
            # Pure text input - use spam model
            results['analysis_type'].append('Text')
            text_features = tfidf_vectorizer.transform([user_input])
            text_prediction = spam_classifier.predict(text_features)[0]
            text_confidence = max(spam_classifier.predict_proba(text_features)[0])
            
            results['predictions']['text'] = int(text_prediction)
            results['risk_scores']['text'] = get_risk_score(text_prediction, text_confidence)
        
        # Calculate combined risk and final prediction
        risk_scores = list(results['risk_scores'].values())
        results['combined_risk'] = int(np.mean(risk_scores))
        
        # Determine final prediction
        if results['combined_risk'] > 60:
            results['final_prediction'] = 'Phishing' if 'URL' in results['analysis_type'] else 'Spam'
        elif results['combined_risk'] > 30:
            results['final_prediction'] = 'Suspicious'
        else:
            results['final_prediction'] = 'Safe'
        
        # Get suggested action and badge
        results['suggested_action'] = get_suggested_action(
            1 if results['final_prediction'] != 'Safe' else 0, 
            results['combined_risk']
        )
        results['badge'], results['badge_class'] = get_badge_level(results['combined_risk'])
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({
            'error': f'Analysis failed: {str(e)}'
        }), 500

@app.route('/analyze-screenshot', methods=['POST'])
def analyze_screenshot():
    """Analyze uploaded screenshot for phishing/spam detection"""
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Please upload PNG, JPG, JPEG, GIF, BMP, or TIFF'}), 400
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # Extract text from image using OCR
        extracted_text, ocr_error = extract_text_from_image(filepath)
        
        if ocr_error:
            # Clean up file
            os.remove(filepath)
            return jsonify({'error': f'OCR failed: {ocr_error}'}), 500
        
        if not extracted_text or len(extracted_text.strip()) < 5:
            # Clean up file
            os.remove(filepath)
            return jsonify({'error': 'No readable text found in the image'}), 400
        
        # Analyze the extracted text
        analysis_result = analyze_extracted_text(extracted_text)
        
        # Add image data for preview
        try:
            with open(filepath, 'rb') as img_file:
                img_data = base64.b64encode(img_file.read()).decode('utf-8')
                file_extension = filename.rsplit('.', 1)[1].lower()
                analysis_result['image_preview'] = f"data:image/{file_extension};base64,{img_data}"
        except Exception as e:
            print(f"Error encoding image: {e}")
            analysis_result['image_preview'] = None
        
        # Clean up file
        os.remove(filepath)
        
        return jsonify(analysis_result)
        
    except Exception as e:
        return jsonify({'error': f'Screenshot analysis failed: {str(e)}'}), 500

def analyze_extracted_text(text):
    """Analyze extracted text for phishing/spam detection"""
    try:
        # Check if models are loaded
        if not all([phishing_model, vectorizer, spam_classifier, tfidf_vectorizer]):
            print("⚠️ Models not loaded, using mock analysis for screenshot")
            results = mock_analysis(text)
            results['warning'] = 'Using mock analysis - models not loaded'
            results['extracted_text'] = text
            return results
        
        results = {
            'extracted_text': text,
            'analysis_type': [],
            'predictions': {},
            'risk_scores': {},
            'combined_risk': 0,
            'final_prediction': 'Safe',
            'suggested_action': '',
            'badge': '',
            'badge_class': ''
        }
        
        # Determine input type and run appropriate models
        is_url_input = is_url(text)
        has_urls = contains_url(text)
        
        if is_url_input:
            # Pure URL input - use phishing model
            results['analysis_type'].append('URL')
            url_features = vectorizer.transform([text])
            url_prediction = phishing_model.predict(url_features)[0]
            url_confidence = max(phishing_model.predict_proba(url_features)[0])
            
            results['predictions']['url'] = int(url_prediction)
            results['risk_scores']['url'] = get_risk_score(url_prediction, url_confidence)
            
        elif has_urls:
            # Text with URLs - run both models
            results['analysis_type'].extend(['URL', 'Text'])
            
            # Extract first URL for phishing analysis
            urls = extract_urls(text)
            url_features = vectorizer.transform([urls[0]])
            url_prediction = phishing_model.predict(url_features)[0]
            url_confidence = max(phishing_model.predict_proba(url_features)[0])
            
            # Text analysis for spam
            text_features = tfidf_vectorizer.transform([text])
            text_prediction = spam_classifier.predict(text_features)[0]
            text_confidence = max(spam_classifier.predict_proba(text_features)[0])
            
            results['predictions']['url'] = int(url_prediction)
            results['predictions']['text'] = int(text_prediction)
            results['risk_scores']['url'] = get_risk_score(url_prediction, url_confidence)
            results['risk_scores']['text'] = get_risk_score(text_prediction, text_confidence)
            
        else:
            # Pure text input - use spam model
            results['analysis_type'].append('Text')
            text_features = tfidf_vectorizer.transform([text])
            text_prediction = spam_classifier.predict(text_features)[0]
            text_confidence = max(spam_classifier.predict_proba(text_features)[0])
            
            results['predictions']['text'] = int(text_prediction)
            results['risk_scores']['text'] = get_risk_score(text_prediction, text_confidence)
        
        # Calculate combined risk and final prediction
        risk_scores = list(results['risk_scores'].values())
        results['combined_risk'] = int(np.mean(risk_scores))
        
        # Determine final prediction
        if results['combined_risk'] > 60:
            results['final_prediction'] = 'Phishing' if 'URL' in results['analysis_type'] else 'Spam'
        elif results['combined_risk'] > 30:
            results['final_prediction'] = 'Suspicious'
        else:
            results['final_prediction'] = 'Safe'
        
        # Get suggested action and badge
        results['suggested_action'] = get_suggested_action(
            1 if results['final_prediction'] != 'Safe' else 0, 
            results['combined_risk']
        )
        results['badge'], results['badge_class'] = get_badge_level(results['combined_risk'])
        
        return results
        
    except Exception as e:
        return {
            'extracted_text': text,
            'error': f'Text analysis failed: {str(e)}',
            'final_prediction': 'Error',
            'combined_risk': 0
        }

@app.route('/health')
def health():
    """Health check endpoint"""
    models_loaded = all([phishing_model, vectorizer, spam_classifier, tfidf_vectorizer])
    return jsonify({
        'status': 'healthy' if models_loaded else 'models_missing',
        'models_loaded': models_loaded,
        'python_version': sys.version,
        'available_models': {
            'phishing_model': phishing_model is not None,
            'vectorizer': vectorizer is not None,
            'spam_classifier': spam_classifier is not None,
            'tfidf_vectorizer': tfidf_vectorizer is not None
        }
    })

if __name__ == '__main__':
    print("🚀 Starting Phishing & Spam Detection App...")
    print("📦 Loading AI models...")
    
    if load_models():
        print("🎯 App ready! Starting server...")
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("⚠️ Models not loaded, but starting app with mock analysis...")
        print("You can still test the UI and see how the app works!")
        app.run(debug=True, host='0.0.0.0', port=5000) 