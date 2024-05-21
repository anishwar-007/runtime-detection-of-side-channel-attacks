# Documentation for Determining the Optimal Threshold for Attack Detection Using ROC Curve

## Overview

This document describes the process of determining the optimal threshold for detecting attacks using Receiver Operating Characteristic (ROC) curve analysis. Two datasets, attack.csv and no_attack.csv, are used. The optimal threshold is identified using the ROC curve and the Area Under the Curve (AUC) is calculated to assess the model's performance.


## Why ROC Analysis?

    Performance Assessment: ROC analysis provides a comprehensive way to assess the performance of a binary classification model. It considers the trade-offs between the true positive rate (TPR) and the false positive rate (FPR) across various threshold settings.

    Threshold Selection: In many classification tasks, the output of the model is a probability score or a continuous value. Setting a threshold on this score determines the classification outcome (e.g., positive or negative). ROC analysis helps in selecting an optimal threshold that balances between correctly identifying positive instances (attacks, in this case) while minimizing false alarms (misclassifying non-attacks).


## Datasets

    attack.csv: Contains data with known attacks.
    no_attack.csv: Contains data with no attacks.

Both datasets include a column named ratio which is used for the analysis.

## How to run

Open the "Threshold using ROC method.ipynb" in a google colab, or jupyter notebook 
and use the attack.csv and no_attack.csv files to display the ROC curve.

# Code Description
## Importing Libraries

python
```
import pandas as pd
import numpy as np
from sklearn.metrics import roc_curve, roc_auc_score
import matplotlib.pyplot as plt
```
## Loading the Data

The CSV files are loaded into Pandas DataFrames.

python
```
no_attack_df = pd.read_csv('no_attack.csv', delimiter=',')
attack_df = pd.read_csv('attack.csv', delimiter=',')
```
## Checking Columns

Ensure that both DataFrames contain the ratio column.

python
```
print("No Attack DataFrame columns:", no_attack_df.columns)
print("Attack DataFrame columns:", attack_df.columns)

if 'ratio' not in no_attack_df.columns:
    raise KeyError("The 'ratio' column is not found in no_attack_df")
if 'ratio' not in attack_df.columns:
    raise KeyError("The 'ratio' column is not found in attack_df")
```
## Data Preprocessing

Convert the ratio column to numeric and drop rows with NaN values.

python
```
no_attack_df['ratio'] = pd.to_numeric(no_attack_df['ratio'], errors='coerce')
attack_df['ratio'] = pd.to_numeric(attack_df['ratio'], errors='coerce')

no_attack_df.dropna(subset=['ratio'], inplace=True)
attack_df.dropna(subset=['ratio'], inplace=True)
```
## Labeling Data

Label the data for ROC curve calculation. no_attack data is labeled as 0 and attack data as 1.

python
```
no_attack_df['label'] = 0
attack_df['label'] = 1
```
## Combining the Data

Combine the data into a single DataFrame.

python

combined_df = pd.concat([no_attack_df[['ratio', 'label']], attack_df[['ratio', 'label']]], ignore_index=True)

## Extracting Ratios and Labels

Extract the ratio values and corresponding labels.

python
```
data = combined_df['ratio'].values
labels = combined_df['label'].values
```
## Calculating ROC Curve and AUC

Calculate the ROC curve and the AUC score.

python
```
fpr, tpr, thresholds = roc_curve(labels, data)
roc_auc = roc_auc_score(labels, data)

print(f"AUC: {roc_auc}")
```
## Finding the Optimal Threshold

Calculate the distance to the top-left corner (0,1) of the ROC curve and find the threshold that minimizes this distance.

python
```
distances = np.sqrt((fpr - 0)**2 + (tpr - 1)**2)
optimal_index = np.argmin(distances)
optimal_threshold = thresholds[optimal_index]

print(f"Optimal Threshold: {optimal_threshold}")
```
## Applying the Threshold

Define a function to classify data points based on the optimal threshold and calculate false positive and true positive rates.

python
```
def is_attack(ratio):
    return ratio > optimal_threshold

false_positives = [is_attack(ratio) for ratio in no_attack_df['ratio']]
true_positives = [is_attack(ratio) for ratio in attack_df['ratio']]

false_positive_rate = sum(false_positives) / len(false_positives)
true_positive_rate = sum(true_positives) / len(true_positives)

print(f"False Positive Rate: {false_positive_rate * 100}%")
print(f"True Positive Rate: {true_positive_rate * 100}%")
```
## Plotting the ROC Curve

Plot the ROC curve and highlight the optimal threshold.

python
```
plt.figure()
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:0.2f})')
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.scatter(fpr[optimal_index], tpr[optimal_index], color='red', label='Optimal Threshold', zorder=10)
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic')
plt.legend(loc="lower right")
plt.show()
```
## Conclusion

The optimal threshold for detecting attacks based on the ROC curve analysis is 87.6. This threshold provides a balance between the true positive rate and the false positive rate, optimizing the model's performance in identifying attacks.