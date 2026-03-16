import numpy as np
from sklearn.linear_model import LogisticRegression
import re
import math

def calculate_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"\W", password): charset += 32
    if charset == 0: return 0
    return len(password) * math.log2(charset)

def extract_features(password):
    return [
        len(password),
        len(re.findall(r"[A-Z]", password)),
        len(re.findall(r"[a-z]", password)),
        len(re.findall(r"[0-9]", password)),
        len(re.findall(r"\W", password)),
        calculate_entropy(password)
    ]

# Simple training dataset
passwords = [
    ("123456", 0),
    ("password", 0),
    ("Sachin123", 1),
    ("S@chin2026!", 2),
    ("T7$kP9!vX2@", 3),
]

X = np.array([extract_features(p[0]) for p in passwords])
y = np.array([p[1] for p in passwords])

model = LogisticRegression(max_iter=1000)
model.fit(X, y)

def predict_strength(password):
    features = np.array(extract_features(password)).reshape(1, -1)
    return int(model.predict(features)[0])