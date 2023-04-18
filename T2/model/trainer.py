""" Arquivo de Treinamento dos modelo de deteccao de DoS"""
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn import metrics


class Classifiers:
    rf = RandomForestClassifier(max_depth=20, class_weight='balanced', random_state=42)
    dt = DecisionTreeClassifier(max_depth=10, class_weight='balanced', random_state=42)
    nn = MLPClassifier(alpha=0.5, max_iter=1000)
    knn = KNeighborsClassifier()

    def __init__(self):
        df_normal = pd.read_csv('results.csv')
        df_attack = pd.read_csv('attack.csv')

        df_normal = df_normal.diff(periods=-1).abs()[:-1]
        df_attack = df_attack.diff(periods=-1).abs()[:-1]

        df_normal = df_normal.drop_duplicates(keep='last')
        df_attack = df_attack.drop_duplicates(keep='last')

        df_normal['results'] = np.zeros(df_normal.shape[0], dtype='bool')
        df_attack['results'] = np.ones(df_attack.shape[0], dtype='bool')
        frames = [df_normal, df_attack]

        self.df = pd.concat(frames)

        X = self.df.drop(['results'], axis=1)
        X = X.diff().abs()
        X = X.dropna(axis=0)

        self.X = X.values
        self.y = self.df['results'].values[1:]
        print(self.X.shape)
        print(self.y.shape)
        print(self.X)
        print(self.y)

        self.rf.fit(self.X, self.y) # 75
        self.dt.fit(self.X, self.y) # melhor 80
        self.nn.fit(self.X, self.y) # 75
        self.knn.fit(self.X, self.y)
