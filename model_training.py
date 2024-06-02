import joblib
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from data_processing import process_data

# Пути к данным
normal_node_features_path = 'data/normal_node_features.csv'
phishing_node_features_path = 'data/phishing_node_features.csv'

# Обработка данных и получение признаков и меток
X, y = process_data(normal_node_features_path, phishing_node_features_path)

# Сохранение порядка признаков
feature_order = X.columns.tolist()
print("Feature order:", feature_order)  # Добавим вывод для отладки
joblib.dump(feature_order, 'feature_order.pkl')

# Разделение данных на обучающую и тестовую выборки
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Обучение модели KNN с учетом весов расстояний
knn = KNeighborsClassifier(n_neighbors=5, weights='distance')
knn.fit(X_train, y_train)

# Сохранение обученной модели
joblib.dump(knn, 'knn_model.pkl')

# Оценка модели
accuracy = knn.score(X_test, y_test)
print(f'Model accuracy: {accuracy}')
