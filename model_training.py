import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier

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

# Save the updated dataset
df_normal.to_csv(normal_node_features_path, index=False)
df_phishing.to_csv(phishing_node_features_path, index=False)

# Process data and get features and labels
def process_data(normal_node_features_path, phishing_node_features_path):
    normal_df = pd.read_csv(normal_node_features_path)
    phishing_df = pd.read_csv(phishing_node_features_path)

    df = pd.concat([normal_df, phishing_df], ignore_index=True)
    df = df.select_dtypes(include=[int, float])

    X = df.drop(columns=['label'])
    y = df['label']

    return X, y

X, y = process_data(normal_node_features_path, phishing_node_features_path)

# Save feature order
feature_order = X.columns.tolist()

print("Feature order:", feature_order)  # Debugging output
joblib.dump(feature_order, 'feature_order.pkl')

# Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train KNN model with distance weights
knn = KNeighborsClassifier(n_neighbors=5, weights='distance')
knn.fit(X_train, y_train)

# Save trained model
joblib.dump(knn, 'knn_model.pkl')

# Evaluate model
accuracy = knn.score(X_test, y_test)
print(f'Model accuracy: {accuracy}')
