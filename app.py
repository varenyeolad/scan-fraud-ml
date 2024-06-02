from flask import Flask, request, jsonify
import joblib
import shap
from data_processing import extract_features

# Инициализация Flask приложения
app = Flask(__name__)

def calculate_risk_score(probability):
    return probability[1]

def determine_risk_band(risk_score):
    if risk_score >= 0.8:
        return 1  # Very High Risk
    elif risk_score >= 0.6:
        return 2  # High Risk
    elif risk_score >= 0.4:
        return 3  # Medium Risk
    elif risk_score >= 0.2:
        return 4  # Low Risk
    else:
        return 5  # Very Low Risk

def get_shap_explanation(model, features):
    try:
        explainer = shap.KernelExplainer(model.predict_proba, features)
        shap_values = explainer.shap_values(features)
        feature_importance = {
            feature: shap_value for feature, shap_value in zip(features.columns, shap_values[1][0])
        }
        sorted_importance = dict(sorted(feature_importance.items(), key=lambda item: abs(item[1]), reverse=True))
        return sorted_importance
    except Exception as e:
        print(f"SHAP explanation error: {e}")
        return {"error": str(e)}

def generate_text_summary(explanation, risk_band):
    if 'error' in explanation:
        return "An error occurred while generating the explanation."

    summary = f"The address has been classified with a risk band level of {risk_band}. This is due to the following factors:\n\n"
    for feature, value in explanation.items():
        if value > 0:
            summary += f"- The feature '{feature}' has a positive impact of {value:.2f} on the risk score, indicating higher risk.\n"
        else:
            summary += f"- The feature '{feature}' has a negative impact of {value:.2f} on the risk score, indicating lower risk.\n"
    return summary

@app.route('/scan', methods=['POST'])
def scan_address():
    data = request.json
    address = data.get('address')
    
    if not address:
        return jsonify({'error': 'Address is required'}), 400
    
    # Загрузка порядка признаков
    try:
        feature_order = joblib.load('feature_order.pkl')
    except FileNotFoundError:
        return jsonify({'error': 'Feature order file not found'}), 500
    
    # Извлечение признаков
    features = extract_features(address, feature_order)
    
    # Проверка полученных признаков
    print("Extracted features:", features)
    
    # Загрузка модели
    try:
        model = joblib.load('knn_model.pkl')
    except FileNotFoundError:
        return jsonify({'error': 'Model file not found'}), 500
    
    # Предсказание
    try:
        probability = model.predict_proba(features)[0]
        risk_score = calculate_risk_score(probability)
        risk_band = determine_risk_band(risk_score)
    except ValueError as e:
        return jsonify({'error': str(e)}), 500
    
    # Получение объяснения SHAP
    explanation = get_shap_explanation(model, features)
    
    # Генерация текстового объяснения
    summary = generate_text_summary(explanation, risk_band)
    
    return jsonify({
        'address': address,
        'risk_score': risk_score,
        'risk_band': risk_band,
        'probability': probability.tolist(),
        'explanation': explanation,
        'summary': summary
    })

if __name__ == '__main__':
    app.run(debug=True)
