# 🛡️ AI-Powered Malware Detection System

This project implements an advanced malware detection system using ensemble machine learning to analyze PDF, DOCX, DOC, and JSON files for potential malicious content.

## 🎯 Features

- **Multi-Model Ensemble Detection**: Combines three powerful ML models:
  - Random Forest (40% weight)
  - XGBoost (40% weight)
  - Neural Network (20% weight)
- **Supported File Types**: PDF, DOCX, DOC, JSON
- **Real-time Analysis**: Instant scanning with detailed reports
- **Feature Extraction**: Comprehensive analysis of file characteristics
- **Web Interface**: User-friendly Gradio interface for file uploads
- **Detailed Reporting**: Includes confidence scores, threat levels, and specific indicators

## 📊 Performance Metrics

- **Dataset**: CIC-Evasive-PDFMal2022 (10,025 samples)
- **Accuracy**: ~95%
- **Precision**: High precision for malware detection
- **False Positive Rate**: Low false positive rate
- **ROC-AUC**: Strong classification performance

## 🚀 Setup Instructions

1. **Clone the Repository**
   ```bash
   git clone <repository-url>
   cd ransomware-ml
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv .venv
   ```

3. **Activate Virtual Environment**
   - Windows:
     ```powershell
     .venv\Scripts\activate
     ```
   - Linux/Mac:
     ```bash
     source .venv/bin/activate
     ```

4. **Install Dependencies**
   ```bash
   pip install gradio pandas numpy PyPDF2 python-docx scikit-learn xgboost imbalanced-learn shap matplotlib seaborn joblib
   ```

5. **Download Dataset**
   - Download `CIC-Evasive-PDFMal2022.parquet` from [Kaggle](https://www.kaggle.com/datasets/strgenix/cic-evasive-pdfmal2022)
   - Place it in the `data/` directory as `PDFMalware2022.parquet`

## 💻 Usage

1. **Start the Application**
   ```bash
   python project.py
   ```

2. **Access the Web Interface**
   - Open the URL shown in the terminal (typically http://127.0.0.1:7860)
   - The interface will also be available via a public URL (expires in 72 hours)

3. **Analyze Files**
   - Upload any PDF, DOCX, DOC, or JSON file (max 50MB)
   - Click "Scan for Malware"
   - Review the detailed analysis report

## 📋 Analysis Report Features

The system provides comprehensive analysis including:
- Overall prediction (Benign/Malicious)
- Confidence score
- Threat level (Safe, Low, Medium, High, Critical)
- Individual model predictions
- Top 5 important features detected
- Detailed recommendations based on scan results

## 🔍 Feature Extraction

The system analyzes various file characteristics including:
- File structure and metadata
- Embedded content and scripts
- Security features
- Document properties
- Suspicious elements (JavaScript, actions, etc.)

## 🛠️ Project Structure

```
ransomware-ml/
├── project.py           # Main application file
├── data/               # Dataset directory
│   └── PDFMalware2022.parquet
├── trained_model/       # Saved model files
│   ├── trained_models.pkl
│   ├── scaler.pkl
│   ├── feature_names.pkl
│   ├── feature_importance.pkl
│   └── feature_stats.pkl
└── model_evaluation.png # Performance visualizations
```

## ⚠️ Important Notes

- This tool is for research and defensive purposes only
- Always scan files in a controlled environment
- Keep the models and dataset updated for best results
- Do not use on sensitive or production systems without proper testing

## 🔒 Security Considerations

- The system is designed for analysis in controlled environments
- Files are processed in memory for security
- No files are permanently stored
- Analysis is performed locally on your machine

## 📚 Models and Training

The system uses an ensemble of three models:
1. **Random Forest**
   - 200 estimators
   - Maximum depth: 20
   - Balanced class weights

2. **XGBoost**
   - 200 estimators
   - Maximum depth: 10
   - Learning rate: 0.1

3. **Neural Network**
   - Architecture: 128 → 64 → 32 neurons
   - ReLU activation
   - Adaptive learning rate

## 🤝 Contributing

Contributions to improve the system are welcome. Please ensure:
- Code follows the existing style
- All tests pass
- Documentation is updated
- No malicious content is included

## 📄 License

This project is intended for research and educational purposes only. Use responsibly.

## 🙏 Acknowledgments

- Dataset provided by the Canadian Institute for Cybersecurity (CIC)
- Built with scikit-learn, XGBoost, and Gradio