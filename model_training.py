import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
import numpy as np

# Paths to data
normal_node_features_path = 'data/normal_node_features_corrected.csv'
phishing_node_features_path = 'data/phishing_node_features_corrected.csv'

# Load your existing dataset
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
X = df_combined.drop(columns=['label', 'address'])
y = df_combined['label']

# Calculate class weights
class_weights = compute_class_weight(class_weight='balanced', classes=np.unique(y), y=y)
class_weight_dict = {i: class_weights[i] for i in range(len(class_weights))}

# Save feature order
feature_order = X.columns.tolist()
print("Feature order:", feature_order)  # Debugging output
joblib.dump(feature_order, 'feature_order.pkl')

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Normalize features
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Train Logistic Regression model with class weights
log_reg = LogisticRegression(class_weight=class_weight_dict, max_iter=1000)
log_reg.fit(X_train, y_train)

# Save trained model and scaler
joblib.dump(log_reg, 'log_reg_model.pkl')
joblib.dump(scaler, 'scaler.pkl')

# Evaluate model
accuracy = log_reg.score(X_test, y_test)
print(f'Model accuracy: {accuracy}')
