import pandas as pd
import matplotlib.pyplot as plt

# Read the data from CSV file
data = pd.read_csv('data.csv')

# Plot the frequency curve
plt.hist(data['values'], bins=100, density=True, histtype='step', cumulative=False, label='DF')
plt.title('Frequency Curve')
plt.xlabel('Values')
plt.ylabel('Frequency')
plt.legend(loc='upper left')
plt.grid(True)
plt.show()

