# SCAN SCAM API

## Overview
A machine learning-based project designed to classify blockchain addresses as either normal or phishing addresses. It utilizes a K-Nearest Neighbors (KNN) classifier to detect and flag potentially malicious addresses based on their transactional features. The project involves data preprocessing, handling class imbalance, hyperparameter tuning, model training, and evaluation.


## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Features
- Data preprocessing and feature engineering
- Handling class imbalance using SMOTE
- Hyperparameter tuning for KNN using GridSearchCV
- Model calibration using isotonic regression
- API integration with Flask for serving the model
- Redis integration for rate limiting
- Comprehensive logging and error handling

## Installation

### Prerequisites
- Python 3.7+
- PostgreSQL 16
- Redis server
- Virtual environment 

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/varenyeolad/scan-fraud-ml.git
   cd scan-fraud-ml

2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   
4. Set up PostgreSQL and Redis

## Usage
### Running the Machine Learning Script
1. Ensure the virtual environment is activated:

    ```bash
    source venv/bin/activate
    
2. Run the Data Processing Script:

    ```bash
    python scripts/data_processing.py
    
4. Run the ML script to train and evaluate the model:
   
    ```bash
    python scripts/train_model.py
    
5. Run the Application:
   
   ```bash
   python scripts/app.py

## Model Evaluation

The confusion matrix below shows the performance of the trained model on the test dataset.

![Confusion Matrix](https://github.com/varenyeolad/scan-fraud-ml/blob/main/confusion_matrix.png)

## API Usage

- [poWalletExplorer](https://github.com/varenyeolad/poWallet-explorer/tree/master/frontend)
- [poWallet](https://github.com/varenyeolad/powallet-ex-wallet.git)   


