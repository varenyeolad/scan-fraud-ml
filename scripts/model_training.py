import joblib
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import SMOTE
from sklearn.metrics import confusion_matrix, classification_report
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.calibration import CalibratedClassifierCV

# Load your existing dataset
normal_node_features_path = '././data/normal_node_features_corrected.csv'
phishing_node_features_path = '././data/phishing_node_features_corrected.csv'
df_normal = pd.read_csv(normal_node_features_path)
df_phishing = pd.read_csv(phishing_node_features_path)

# Ensure necessary features are included
required_features = [
    'value_out', 'value_in', 'balance', 'degree', 'degree_in', 'degree_out',
    'max_value', 'min_value', 'mean_value', 'std_value', 'median_value',
    'avg_in_tx_interval', 'min_value_out'
]
for feature in required_features:
    if feature not in df_normal.columns:
        df_normal[feature] = 0
    if feature not in df_phishing.columns:
        df_phishing[feature] = 0

# Combine the datasets
df_normal['label'] = 0  # Label for normal addresses
df_phishing['label'] = 1  # Label for phishing addresses
df_combined = pd.concat([df_normal, df_phishing], ignore_index=True)

# Separate features and labels, excluding the 'address' column
X = df_combined.drop(columns=['label', 'address'], errors='ignore')
y = df_combined['label']

# Normalize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Handle class imbalance using SMOTE
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_scaled, y)

# Hyperparameter tuning for KNN
param_grid = {
    'n_neighbors': [3, 5, 7, 9, 11],
    'weights': ['uniform', 'distance'],
    'algorithm': ['ball_tree', 'kd_tree', 'brute']
}
knn = KNeighborsClassifier()
grid_search = GridSearchCV(knn, param_grid, cv=5, scoring='accuracy')
grid_search.fit(X_resampled, y_resampled)

print(f"Best parameters found: {grid_search.best_params_}")
print(f"Best cross-validation accuracy: {grid_search.best_score_}")

# Train the final model with best parameters
best_knn = grid_search.best_estimator_

# Calibrate the classifier
calibrated_knn = CalibratedClassifierCV(estimator=best_knn, method='isotonic', cv=5)
calibrated_knn.fit(X_resampled, y_resampled)

# Save trained model and scaler
joblib.dump(calibrated_knn, 'knn_model.pkl')
joblib.dump(scaler, 'scaler.pkl')

# Evaluate model
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
X_train_scaled = scaler.transform(X_train)
X_test_scaled = scaler.transform(X_test)

y_pred = calibrated_knn.predict(X_test_scaled)
y_pred_proba = calibrated_knn.predict_proba(X_test_scaled)

print(classification_report(y_test, y_pred))
accuracy = calibrated_knn.score(X_test_scaled, y_test)
print(f'Model accuracy: {accuracy}')

# Plot confusion matrix
cm = confusion_matrix(y_test, y_pred)
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Phishing'], yticklabels=['Normal', 'Phishing'])
plt.xlabel('Predicted label')
plt.ylabel('True label')
plt.title('Confusion Matrix')
plt.savefig('confusion_matrix.png')
plt.show()
