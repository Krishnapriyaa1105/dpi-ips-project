from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def evaluate(y_test, y_pred):
    print("\n---- IPS Performance Evaluation ----\n")
    
    print("Accuracy :", accuracy_score(y_test, y_pred))
    print("Precision:", precision_score(y_test, y_pred, pos_label="attack"))
    print("Recall   :", recall_score(y_test, y_pred, pos_label="attack"))
    print("F1 Score :", f1_score(y_test, y_pred, pos_label="attack"))
    
    print("\nConfusion Matrix:\n")
    print(confusion_matrix(y_test, y_pred))

