import math
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestRegressor
from sklearn.linear_model import LinearRegression, Ridge, Lasso
from sklearn.tree import DecisionTreeRegressor
from sklearn.metrics import mean_squared_error
from sklearn.model_selection import train_test_split, cross_val_score, cross_val_predict, GridSearchCV
from sklearn.preprocessing import KBinsDiscretizer, StandardScaler, PolynomialFeatures
from sklearn.pipeline import make_pipeline, Pipeline
from sklearn.decomposition import PCA
import statsmodels.api as sm
import warnings
from sklearn.exceptions import DataConversionWarning
from mpl_toolkits.mplot3d import Axes3D
from sklearn.feature_selection import RFE
import joblib

# Suppress FutureWarnings and DataConversionWarnings
warnings.simplefilter(action='ignore', category=FutureWarning)
warnings.simplefilter(action='ignore', category=DataConversionWarning)


def rssi_to_distance(rssi, pt, n):
    # Convert RSSI to distance using the log-distance path loss model
    return 10 ** ((pt - rssi) / (10 * n))

def toa_to_distance(toa, ref_toa):
    c= 3e8
    return c * (toa - ref_toa)

def triangulate_location_3d_Inverse(group, coords = [(0,0,0),(2,1.5,0),(2,0,0)]):
    # print(f'#####\n{rssi1}\n#####')
    rssi_values = group['RSSIDistance'].tolist()
    # print(rssi_values)
    d1 = rssi_values[0]
    d2 = rssi_values[1]
    d3 = rssi_values[2]


    x1, y1, z1 = coords[0]
    x2, y2, z2 = coords[1]
    x3, y3, z3 = coords[2]

    A = np.array([
        [2*(x2 - x1), 2*(y2 - y1), 2*(z2 - z1)],
        [2*(x3 - x1), 2*(y3 - y1), 2*(z3 - z1)],
    ])
    
    B = np.array([
        d1**2 - d2**2 + x2**2 - x1**2 + y2**2 - y1**2 + z2**2 - z1**2,
        d1**2 - d3**2 + x3**2 - x1**2 + y3**2 - y1**2 + z3**2 - z1**2,
    ])

    try:
        # Use the pseudo-inverse to solve the system
        estimated_location = np.linalg.pinv(A).dot(B).tolist()
    except np.linalg.LinAlgError:
        print("Error: Singular matrix - cannot determine a unique solution.")
        return None

    print(estimated_location)

    return estimated_location

def triangulate_location_toa(receiver_positions = [(0,0,0),(2,1.5,0),(2,0,0)], d2=0, d3=0):
    A = np.array([
        [receiver_positions[1][0] - receiver_positions[0][0], 
         receiver_positions[1][1] - receiver_positions[0][1], 
         receiver_positions[1][2] - receiver_positions[0][2]],
        
        [receiver_positions[2][0] - receiver_positions[0][0], 
         receiver_positions[2][1] - receiver_positions[0][1], 
         receiver_positions[2][2] - receiver_positions[0][2]]
    ])

    B = 0.5 * np.array([
        d2**2 - np.sum(receiver_positions[1]**2) + np.sum(receiver_positions[0]**2),
        d3**2 - np.sum(receiver_positions[2]**2) + np.sum(receiver_positions[0]**2)
    ])

    try:
        # Use the Moore-Penrose pseudo-inverse to solve for the sender's position
        estimated_location = np.linalg.pinv(A).dot(B)
    except np.linalg.LinAlgError:
        print("Error: Singular matrix - cannot determine a unique solution.")
        return None
    # estimated_position = np.dot(pseudo_inverse_A, B)

    # Convert the result back to a list and return
    return estimated_location

def convert_to_float_list(string):
    try:
        # Remove brackets and split by commas
        string = string.strip("[]")
        # Convert each part to a float
        return [float(x) for x in string.split(",")]
    except ValueError:
        # Return default value if conversion fails
        return [0.0, 0.0, 0.0]

def apply_binning(df, cols, binList):    
    for col in cols:
        df[col] = pd.cut(df[col], bins=binList, labels=False, include_lowest=True)
        
    return df

def scale_features(X_train, X_test):
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    return X_train_scaled, X_test_scaled

def add_polynomial_features(X_train, X_test, degree=2):
    poly = PolynomialFeatures(degree=degree, include_bias=False)
    X_train_poly = poly.fit_transform(X_train)
    X_test_poly = poly.transform(X_test)
    return X_train_poly, X_test_poly

def evaluate_model(model, X_train, X_test, y_train, y_test):
    # Train the model
    model.fit(X_train, y_train)
    
    # Predict on the test set
    y_pred = model.predict(X_test)
    
    # Calculate RMSE
    mse = mean_squared_error(y_test, y_pred)
    rmse = math.sqrt(mse)
    print(f'{model.__class__.__name__}: RMSE = {rmse:.4f}')
    
    # Ensure that y_test and y_pred are converted to NumPy arrays
    y_test_np = y_test.to_numpy() if isinstance(y_test, pd.DataFrame) else np.array(y_test)
    y_pred_np = y_pred if isinstance(y_pred, np.ndarray) else np.array(y_pred)
    
    # Create a 3D scatter plot comparing predicted vs actual values
    fig = plt.figure(figsize=(10, 8))
    ax = fig.add_subplot(111, projection='3d')
    
    # Scatter plot for actual values (y_test)
    ax.scatter(y_test_np[:, 0], y_test_np[:, 1], y_test_np[:, 2], color='blue', label='Actual', marker='o')
    
    # Scatter plot for predicted values (y_pred)
    ax.scatter(y_pred_np[:, 0], y_pred_np[:, 1], y_pred_np[:, 2], color='red', label='Predicted', marker='^')
    
    # Set labels and title
    ax.set_xlabel('X')
    ax.set_ylabel('Y')
    ax.set_zlabel('Z')
    ax.set_title(f'{model.__class__.__name__}: Actual vs Predicted (3D)')
    
    # Add legend
    ax.legend()
    
    # Show the plot
    plt.show()
    
    return y_pred

def evaluate_model_with_overfitting_check(model, X_train, X_test, y_train, y_test):
    model.fit(X_train, y_train)
    
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)
    
    mse_train = mean_squared_error(y_train, y_train_pred)
    rmse_train = math.sqrt(mse_train)
    
    mse_test = mean_squared_error(y_test, y_test_pred)
    rmse_test = math.sqrt(mse_test)
    
    print(f'{model.__class__.__name__} - Training RMSE: {rmse_train:.4f}, Test RMSE: {rmse_test:.4f}\n')
    
    if rmse_test > rmse_train * 1.2:  # Arbitrary threshold, 20% worse on test
        print(f'Warning: {model.__class__.__name__} is likely overfitting\n')

    return y_test_pred

def cross_validate_model(model, X, y):
    # Perform cross-validation and calculate RMSE scores
    scores = -cross_val_score(model, X, y, cv=5, scoring='neg_mean_squared_error')
    rmse_scores = np.sqrt(scores)
    print(f'{model.__class__.__name__} - Cross-validated RMSE: {rmse_scores.mean():.4f} ± {rmse_scores.std():.4f}')
    
    # Get cross-validated predictions
    y_pred = cross_val_predict(model, X, y, cv=5)
    
    # # Ensure that y_test and y_pred are converted to NumPy arrays
    # y_test_np = y_test.to_numpy() if isinstance(y_test, pd.DataFrame) else np.array(y_test)
    # y_pred_np = y_pred if isinstance(y_pred, np.ndarray) else np.array(y_pred)
    
    # # Create a 3D scatter plot comparing predicted vs actual values
    # fig = plt.figure(figsize=(10, 8))
    # ax = fig.add_subplot(111, projection='3d')
    
    # # Scatter plot for actual values (y_test)
    # ax.scatter(y_test_np[:, 0], y_test_np[:, 1], y_test_np[:, 2], color='blue', label='Actual', marker='o')
    
    # # Scatter plot for predicted values (y_pred)
    # ax.scatter(y_pred_np[:, 0], y_pred_np[:, 1], y_pred_np[:, 2], color='red', label='Predicted', marker='^')
    
    # # Set labels and title
    # ax.set_xlabel('X')
    # ax.set_ylabel('Y')
    # ax.set_zlabel('Z')
    # ax.set_title(f'{model.__class__.__name__}: Actual vs Predicted (3D)')
    
    # # Add legend
    # ax.legend()
    # plt.show()

def print_model_statistics(model, X_train, y_train, component_names=['_x', '_y', '_z']):
    if isinstance(X_train, pd.DataFrame):
        feature_names = X_train.columns
    else:
        feature_names = [f'Feature_{i}' for i in range(X_train.shape[1])]
    
    if isinstance(model, (LinearRegression, Ridge, Lasso)):
        for i, component in enumerate(component_names):
            print(f"\n--- Statistics for {component} ---")
            y_train_component = y_train.iloc[:, i]
            X_train_const = sm.add_constant(X_train)
            ols_model = sm.OLS(y_train_component, X_train_const).fit()

            # Column headers with better alignment
            print(f"{'Feature':<25}{'Coef':>15}{'Std Err':>15}{'t':>15}{'P>|t|':>15}{'[0.025':>15}{'0.975]':>15}")

            # Print each row of statistics with better formatting for large values
            for j, coef in enumerate(ols_model.params):
                feature_name = feature_names[j - 1] if j > 0 else 'Intercept'
                print(f"{feature_name:<25}"
                      f"{coef:>15.6e}"   # Coefficient in scientific notation
                      f"{ols_model.bse[j]:>15.6e}"   # Std error
                      f"{ols_model.tvalues[j]:>15.6f}"  # t-value
                      f"{ols_model.pvalues[j]:>15.6f}"  # p-value
                      f"{ols_model.conf_int()[0][j]:>15.6e}"  # Confidence interval lower bound
                      f"{ols_model.conf_int()[1][j]:>15.6e}")  # Confidence interval upper bound
    
    elif hasattr(model, 'feature_importances_'):
        print(f"\n--- Feature Importances ---")
        print(f"{'Feature':<25}{'Importance':>15}")
        for i, importance in enumerate(model.feature_importances_):
            print(f"{feature_names[i]:<25}{importance:>15.6f}")
    
    else:
        print(f"{model.__class__.__name__} does not provide coefficients or feature importances.")





file_name = 'trainSetSynth.csv'
# colnames = ['rssi1','rssi2','rssi3','pt1','pt2','pt3','n1','n2','n3','loc1','loc2','loc3','RSSILoc','TrueLoc']
base = pd.read_csv(file_name)
df = base
# print(df.head())

# print(df.info())

for col in ['loc1', 'loc2', 'loc3', 'RSSILoc', 'TrueLoc']:
    df[col] = df[col].apply(convert_to_float_list)

for col in ['loc1', 'loc2', 'loc3', 'RSSILoc', 'TrueLoc']:
    df[col] = df[col].apply(lambda x: x if isinstance(x, list) and len(x) == 3 else [0.0, 0.0, 0.0])

for col in ['loc1', 'loc2', 'loc3', 'RSSILoc', 'TrueLoc']:
    df[[f'{col}_x', f'{col}_y', f'{col}_z']] = pd.DataFrame(df[col].tolist(), index=df.index)

# df['d1'] = rssi_to_distance()
df['distance1'] = df.apply(lambda row: rssi_to_distance(row['rssi1'], row['pt1'], row['n1']), axis=1)
df['distance2'] = df.apply(lambda row: rssi_to_distance(row['rssi2'], row['pt2'], row['n2']), axis=1)
df['distance3'] = df.apply(lambda row: rssi_to_distance(row['rssi3'], row['pt3'], row['n3']), axis=1)
print(df.describe())
# print(df.head(5))
# Drop original list columns after expanding them
df = df.drop(columns=['loc1', 'loc2', 'loc3', 'RSSILoc', 'TrueLoc'])


# sns.pairplot(df)
# plt.show()

# plt.figure(figsize=(10, 8))
# sns.heatmap(df.corr(), annot=True, cmap='coolwarm', fmt=".2f")
# plt.show()

# Binning for RSSI values
rssiBins = [-100, -70, -65, -60, -55, -50, -45, -40, -35, -30, -25, -20, 0]
X_binned = apply_binning(df, ['rssi1', 'rssi2', 'rssi3'], rssiBins)

# Set up feature and target variables
# ['loc1_x','loc1_y','loc1_z','loc2_x','loc2_y','loc2_z','loc3_x','loc3_y','loc3_z']
X = X_binned.drop(columns=['TrueLoc_x', 'TrueLoc_y', 'TrueLoc_z'])
y = df[['TrueLoc_x', 'TrueLoc_y', 'TrueLoc_z']]

#drop columns
print(X.head(5))
# X = X.drop(columns=[''])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3)

# Compare calculatedLoc (log-distance trilateration) to TrueLoc
y_test_calculated = X_test[['RSSILoc_x', 'RSSILoc_y', 'RSSILoc_z']]
mse_calculated = mean_squared_error(y_test, y_test_calculated)
rmse_calculated = math.sqrt(mse_calculated)
print(f'\n\nCalculatedLoc vs TrueLoc: RMSE = {rmse_calculated:.4f}')

# Models to evaluate
models = [
    LinearRegression(),
    Ridge(alpha=100.0),
    Lasso(alpha=0.01, max_iter=1000)
    # RandomForestRegressor(n_estimators=100, max_depth=20),
    # DecisionTreeRegressor()
]

# Scale features
X_train_scaled, X_test_scaled = scale_features(X_train, X_test)

# Add polynomial features
X_train_poly, X_test_poly = add_polynomial_features(X_train_scaled, X_test_scaled, degree=2)

# PCA for dimensionality reduction
pca = PCA()
X_train_pca = pca.fit_transform(X_train_poly)

# Plot the cumulative explained variance to choose the number of components
explained_variance_ratio = np.cumsum(pca.explained_variance_ratio_)

plt.figure(figsize=(8, 6))
plt.plot(np.arange(1, len(explained_variance_ratio) + 1), explained_variance_ratio, marker='o', linestyle='--')
plt.xlabel('Number of Principal Components')
plt.ylabel('Cumulative Explained Variance')
plt.title('Cumulative Explained Variance by PCA Components')
plt.grid(True)
plt.show()

# Determine the number of components that explain ~95% of the variance
variance_threshold = 0.95
n_components = np.argmax(explained_variance_ratio >= variance_threshold) + 1
print(f'Number of components to retain {variance_threshold*100}% variance: {n_components}')

# Now apply PCA with the selected number of components
pca = PCA(n_components=n_components)
X_train_pca = pca.fit_transform(X_train_poly)
X_test_pca = pca.transform(X_test_poly)



# Ridge and Lasso regularization models
ridge_model = make_pipeline(StandardScaler(), Ridge())
# lasso_model = make_pipeline(StandardScaler(), Lasso(alpha=0.01, max_iter=1000))

# # Add regularization models to the list
# models.extend([ridge_model, lasso_model])

# #### Feature Selection #### #
# Recursive Feature Elimination (RFE) with a linear model
# rfe = RFE(LinearRegression(), n_features_to_select=5)
# rfe.fit(X_train_scaled, y_train)
# X_train_rfe = rfe.transform(X_train_scaled)
# X_test_rfe = rfe.transform(X_test_scaled)
# print("RFE selected features:", rfe.get_support(indices=True))

# Lasso for feature selection (based on coefficients)
# lasso_selector = Lasso(alpha=0.01)
# lasso_selector.fit(X_train_scaled, y_train)
# print("Lasso selected features:", np.nonzero(lasso_selector.coef_)[0])

# Add RFE-transformed models
# models.append(rfe)

# #### Model Selection #### #
# Define hyperparameters for RandomForest and Ridge
# param_grid_rf = {
#     'n_estimators': [10, 50, 100],
#     'max_depth': [None, 10, 20]
# }
param_grid_ridge = {
    'ridge__alpha': [0.1, 1.0, 10.0, 50.0, 100.0, 1000.0, 10000.0]
}

# Grid search for RandomForest
# grid_search_rf = GridSearchCV(RandomForestRegressor(), param_grid_rf, cv=5)
# grid_search_rf.fit(X_train_scaled, y_train)
# print("Best RandomForest params:", grid_search_rf.best_params_)

# # Grid search for Ridge
grid_search_ridge = GridSearchCV(ridge_model, param_grid_ridge, cv=5)
grid_search_ridge.fit(X_train_scaled, y_train)
print("Best Ridge params:", grid_search_ridge.best_params_)


# print(X_train.head())

# Standard model evaluation
print('\n#############\nStandard\n')
for model in models:
    evaluate_model(model, X_train, X_test, y_train, y_test)
    # print_model_statistics(model, X_train, y_train)  # Print model statistics for each model

# Scaled model evaluation
# print('\n#############\nScaled\n')
# for model in models:
#     evaluate_model(model, X_train_scaled, X_test_scaled, y_train, y_test)

# Polynomial model evaluation
# print('\n#############\nPolynomial\n')
# for model in models:
#     evaluate_model(model, X_train_poly, X_test_poly, y_train, y_test)

print('\n#############\nPCA\n')
for model in models:
    evaluate_model(model, X_train_pca, X_test_pca, y_train, y_test)

# Overfitting check
print('\n####_Standard_Check_###\n')
for model in models:
    cross_validate_model(model, X, y)
    # print(f'standard')
    evaluate_model_with_overfitting_check(model, X_train, X_test, y_train, y_test)
    # print(f'scaled')
    # evaluate_model_with_overfitting_check(model, X_train_scaled, X_test_scaled, y_train, y_test)
    # print(f'poly')
    # evaluate_model_with_overfitting_check(model, X_train_poly, X_test_poly, y_train, y_test)

# print('\n####_Scaled_Check_###\n')
# for model in models:
#     cross_validate_model(model, X, y)
#     # print(f'standard')
#     evaluate_model_with_overfitting_check(model, X_train_scaled, X_test_scaled, y_train, y_test)

# print('\n####_Poly_Check_###\n')
# for model in models:
#     cross_validate_model(model, X, y)
#     # print(f'standard')
#     evaluate_model_with_overfitting_check(model,X_train_poly, X_test_poly, y_train, y_test)

print('\n####_PCA_Check_###\n')
for model in models:
    cross_validate_model(model, X, y)
    # print(f'standard')
    evaluate_model_with_overfitting_check(model, X_train_pca, X_test_pca, y_train, y_test)


# print_model_statistics(LinearRegression(), X_train, y_train)  # Print model statistics for each model


#################
# 3d plot of actual, predicted, log-distance, and sniffer locations

# predmodel = Ridge(alpha=10.0)
# predmodel.fit(X_train_pca, y_train)
# index = 3 - 2

# model_y = predmodel.predict(X_test_pca.iloc[[index]])

# # show single prediction
# print(y_test.iloc[[index]])
# print(model_y)



# # Show 3d scatterplot of predicted and actual locations
# y_test_np = y.to_numpy()
# y_pred_np = model_y if isinstance(model_y, np.ndarray) else np.array(model_y)

# snifflist = [[2,1,0],[2,0,0],[0,0,0]]
# sniffer_np = np.array(snifflist)
# y_log_np = np.array(base['RSSILoc'].tolist())

# fig = plt.figure(figsize=(10, 8))
# ax = fig.add_subplot(111, projection='3d')
# ax.set_box_aspect([1, 1, 1])  # Aspect ratio is 1:1:1




# ax.scatter(y_test_np[:, 0], y_test_np[:, 1], y_test_np[:, 2], color='blue', label='Actual', marker='o')
# # ax.scatter(y_pred_np[:, 0], y_pred_np[:, 1], y_pred_np[:, 2], color='black', label='Predicted', marker='^')
# ax.scatter(sniffer_np[:, 0], sniffer_np[:, 1], sniffer_np[:, 2], color='red', label='Sniffer', marker='X')
# # ax.scatter(y_log_np[:, 0], y_log_np[:, 1], y_log_np[:, 2], color='green', label='Log Prediction', marker='^')

# ax.set_xlabel('X')
# ax.set_ylabel('Y')
# ax.set_zlabel('Z')
# ax.set_title(f'{predmodel.__class__.__name__}: Actual vs Predicted (3D)')
# ax.legend()
# plt.show()



################################
# Create pipeline for export

pipeline = Pipeline([
    ('scaling', StandardScaler()),            
    ('polynomial', PolynomialFeatures(degree=2)),
    ('pca', PCA(n_components=n_components)),
    ('ridge', Ridge(alpha=100.0))
])

# Fit the pipeline on your training data
pipeline.fit(X_train, y_train)

# Save the entire pipeline (this includes the transformations and the model)
joblib.dump(pipeline, 'wallflyFitModel.pkl')




################################
# Test pipeline for import

def convert_to_float_list(string):
    try:
        # Remove brackets and split by commas
        string = string.strip("[]")
        # Convert each part to a float
        return [float(x) for x in string.split(",")]
    except ValueError:
        # Return default value if conversion fails
        return [0.0, 0.0, 0.0]

def apply_binning(df, cols, binList):    
    for col in cols:
        df[col] = pd.cut(df[col], bins=binList, labels=False, include_lowest=True)
        
    return df

pipeline = joblib.load('wallflyFitModel.pkl')

# Load the new data
df_new = pd.read_csv('testPipeline.csv')

for col in ['loc1', 'loc2', 'loc3', 'RSSILoc']:
    df_new[col] = df_new[col].apply(convert_to_float_list)

for col in ['loc1', 'loc2', 'loc3', 'RSSILoc']:
    df_new[col] = df_new[col].apply(lambda x: x if isinstance(x, list) and len(x) == 3 else [0.0, 0.0, 0.0])

for col in ['loc1', 'loc2', 'loc3', 'RSSILoc']:
    df_new[[f'{col}_x', f'{col}_y', f'{col}_z']] = pd.DataFrame(df_new[col].tolist(), index=df_new.index)

df_new['distance1'] = df_new.apply(lambda row: rssi_to_distance(row['rssi1'], row['pt1'], row['n1']), axis=1)
df_new['distance2'] = df_new.apply(lambda row: rssi_to_distance(row['rssi2'], row['pt2'], row['n2']), axis=1)
df_new['distance3'] = df_new.apply(lambda row: rssi_to_distance(row['rssi3'], row['pt3'], row['n3']), axis=1)

rssiBins = [-100, -70, -65, -60, -55, -50, -45, -40, -35, -30, -25, -20, 0]
X_binned_new = apply_binning(df_new, ['rssi1', 'rssi2', 'rssi3'], rssiBins)

X_new = X_binned_new.drop(columns=['loc1', 'loc2', 'loc3', 'RSSILoc'])

# The pipeline will handle scaling, polynomial features, PCA, and the model prediction
predictions = pipeline.predict(X_new)

print(predictions[0])