import streamlit as st

import pandas as pd
import numpy as np

import os
import joblib
import hashlib
import pickle

import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')

import lime
import lime.lime_tabular

#BD
from manage import *

from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler  
from sklearn.neighbors import KNeighborsClassifier

def generate_hashes(password):
	return hashlib.sha256(str.encode(password)).hexdigest()

def verify_hashes(password,hashed_text):
	if generate_hashes(password) == hashed_text:
		return hashed_text
	return False

st.set_option('deprecation.showPyplotGlobalUse', False)

@st.cache
def loadData():
	df = pd.read_csv("data/df_1.csv")

	return df

def preprocessing(df):
	X = df.iloc[:,0:79].values
	y = df.iloc[:, -1].values

	le = LabelEncoder()
	y = le.fit_transform(y.flatten())

	X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20, random_state=0)
	return X_train, X_test, y_train, y_test, le


@st.cache(suppress_st_warning=True)
def decisionTree(X_train, X_test, y_train, y_test):
	tree = DecisionTreeClassifier(max_leaf_nodes=3, random_state=0)
	tree.fit(X_train, y_train)
	y_pred = tree.predict(X_test)
	score = metrics.accuracy_score(y_test, y_pred) * 100
	report = classification_report(y_test, y_pred)

	return score, report, tree

@st.cache(suppress_st_warning=True)
def neuralNet(X_train, X_test, y_train, y_test):
	scaler = StandardScaler()  
	scaler.fit(X_train)  
	X_train = scaler.transform(X_train)  
	X_test = scaler.transform(X_test)
	clf = MLPClassifier(solver='lbfgs', alpha=1e-5, hidden_layer_sizes=(5, 2), random_state=1)
	clf.fit(X_train, y_train)
	y_pred = clf.predict(X_test)
	score1 = metrics.accuracy_score(y_test, y_pred) * 100
	report = classification_report(y_test, y_pred)
	
	return score1, report, clf

@st.cache(suppress_st_warning=True)
def Knn_Classifier(X_train, X_test, y_train, y_test):
	clf = KNeighborsClassifier(n_neighbors=5)
	clf.fit(X_train, y_train)
	y_pred = clf.predict(X_test)
	score = metrics.accuracy_score(y_test, y_pred) * 100
	report = classification_report(y_test, y_pred)

	return score, report, clf

def main():
	"""SIDAR - Sistema de Detecção de Ataques"""
	st.sidebar.title("SIDAR - Sistema de Detecção de Ataques")


	menu = ["Sobre o Sistema", "Login", "Cadastro", "Créditos"]
	submenu = ["Análise de Bases"]

	choice = st.sidebar.selectbox("Menu", menu)
	if choice == "Sobre o Sistema":
		st.header("Bem vindo ao SIDAR")

		st.text("O SIDAR - Sistema de Detecção de Ataques em Redes - é a ferramenta on-line para auxiliar os \nusuários que trabalham em setores relacionados à segurança de rede.")
		st.text(" A ferramenta conta com a implementação de métodos de Inteligência Artificial para a predição de \n ataques de negação de serviço em redes de computadores.")

		st.subheader("Por favor faça Login ou Cadastre-se no menu lateral.")

	elif choice == "Login":
		username = st.sidebar.text_input("Username")
		password = st.sidebar.text_input("Password",type='password')
		if st.sidebar.checkbox("Login"):
			create_usertable()
			hashed_pswd = generate_hashes(password)
			result = login_user(username,verify_hashes(password,hashed_pswd))
			# if password == "12345":
			if result:
				st.success("Bem vindo {}".format(username))
				activity = st.selectbox("Função",submenu)
				if activity == "Análise de Bases":
					data = loadData()
					X_train, X_test, y_train, y_test, dt = preprocessing(data)
					st.title("Informe sua base para análise:")
					uploaded_file = st.file_uploader("Faça o upload do seu CSV", type=["csv"])
					choose_model = st.selectbox("Escolha o Modelo",
						["Escolha","Decision Tree", "Neural Network", "K-Nearest Neighbours"])

					if(choose_model == "Decision Tree"):
						score, report, tree = decisionTree(X_train, X_test, y_train, y_test)

						if uploaded_file is not None:
							pred = pd.read_csv(uploaded_file)
							st.dataframe(pred)
							pred = tree.predict(pred)

							index = pd.Index(pred)
							index.value_counts()

							pew = pd.DataFrame(index.value_counts())
							print(pew.values[1])

							result = pew.values[1] / pred.shape
							result = result*100

							st.subheader("Probabilidade de Ataque é de {}%".format(result))

							if result >= 40.0 and result < 70.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido maior que 40% mas menor que 70%, a sua rede PODE ter sofrido um ataque de negação de serivço.")
							elif result >= 70.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido maior que 70%, a sua rede provavelmente SIM sofreu um ataque de negação de serivço.")
							elif result < 40.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido menor que 40%, a sua rede provavelmente NÃO sofreu um ataque de negação de serivço.")

						else:
							st.warning("Nenhum arquivo selecionado")
					
					elif(choose_model == "Neural Network"):
						score, report, clf = neuralNet(X_train, X_test, y_train, y_test)

						if uploaded_file is not None:
							pred = pd.read_csv(uploaded_file)
							scaler = StandardScaler()  
							scaler.fit(X_train)
							pred = scaler.transform(pred)
							st.dataframe(pred)
							pred = clf.predict(pred)


							index = pd.Index(pred)
							index.value_counts()

							pew = pd.DataFrame(index.value_counts())
							print(pew.values[1])

							result = pew.values[1] / pred.shape
							result = result*100

							if result >= 40.0 and result < 70.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido maior que 40% mas menor que 70%, a sua rede PODE ter sofrido um ataque de negação de serivço.")
								st.write(result)
							elif result >= 70.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido maior que 70%, a sua rede provavelmente SIM sofreu um ataque de negação de serivço.")
								st.write(result)
							elif result < 40.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido menor que 40%, a sua rede provavelmente NÃO sofreu um ataque de negação de serivço.")
								st.write(result)

							st.subheader("Probabilidade de Ataque é de {}%".format(result))
						else:
							st.warning("Nenhum arquivo selecionado")

					elif (choose_model == "K-Nearest Neighbours"):
						score, report, clf = Knn_Classifier(X_train, X_test, y_train, y_test)

						if uploaded_file is not None:
							pred = pd.read_csv(uploaded_file)
							st.dataframe(pred)
							pred = clf.predict(pred)

							index = pd.Index(pred)
							index.value_counts()

							pew = pd.DataFrame(index.value_counts())
							print(pew.values[1])

							result = pew.values[1] / pred.shape
							result = result*100

							if result >= 40.0 and result < 70.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido maior que 40% mas menor que 70%, a sua rede PODE ter sofrido um ataque de negação de serivço.")
								st.write(result)
							elif result >= 70.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido maior que 70%, a sua rede provavelmente SIM sofreu um ataque de negação de serivço.")
								st.write(result)
							elif result < 40.0:
								st.warning("Em função do índice de comprometimento da sua coleta ter sido menor que 40%, a sua rede provavelmente NÃO sofreu um ataque de negação de serivço.")
								st.write(result)

							st.subheader("Probabilidade de Ataque é de {} %".format(result))
						else:
							st.warning("Nenhum arquivo selecionado")

			else:
				st.warning("Usuário ou Senha Incorretos")
	elif choice == "Cadastro":
		new_username = st.text_input("Usuário")
		new_password = st.text_input("Senha", type='password')

		confirm_password = st.text_input("Confirme a Senha",type='password')
		if new_password == confirm_password:
			st.success("Senha Confirmada")
		else:
			st.warning("Senha não é a mesma")
		if st.button("Cadastrar"):
			create_usertable()
			hashed_new_password = generate_hashes(new_password)
			add_userdata(new_username, hashed_new_password)
			st.success("Conta Criada")
			st.info("Faça Login")

	elif choice == "Créditos":
		st.header("Créditos")

		st.subheader("Autores:")
		st.text("Davi Oliveira Rebouças - Contato: davireboucas@alu.uern.br")
		st.text("Isaac de Lima Oliveira Filho (orientador) - Contato: issacoliveira@uern.br")

		st.subheader("Co-autores")
		st.text("Emídio Lopes de Souza Neto - Contato: emidioneto@alu.uern.br")
		st.text("João Roberto de Araújo Mendes - Contato: joaomendes@alu.uern.br")

		st.subheader("Créditos:")
		st.text("A base de dados utilizada nesta ferramenta foi desenvolvida pela University of New Brunswick \n em parceria com o Candadian Institute for Cybersecurity")
	else:
		pass

if __name__ == '__main__':
	main()