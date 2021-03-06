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
	"""SIDAR - Sistema de Detec????o de Ataques"""
	st.sidebar.title("SIDAR - Sistema de Detec????o de Ataques")


	menu = ["Sobre o Sistema", "Login", "Cadastro", "Cr??ditos"]
	submenu = ["An??lise de Bases"]

	choice = st.sidebar.selectbox("Menu", menu)
	if choice == "Sobre o Sistema":
		st.header("Bem vindo ao SIDAR")

		st.text("O SIDAR - Sistema de Detec????o de Ataques em Redes - ?? a ferramenta on-line para auxiliar os \nusu??rios que trabalham em setores relacionados ?? seguran??a de rede.")
		st.text(" A ferramenta conta com a implementa????o de m??todos de Intelig??ncia Artificial para a predi????o de \n ataques de nega????o de servi??o em redes de computadores.")

		st.subheader("Por favor fa??a Login ou Cadastre-se no menu lateral.")

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
				activity = st.selectbox("Fun????o",submenu)
				if activity == "An??lise de Bases":
					data = loadData()
					X_train, X_test, y_train, y_test, dt = preprocessing(data)
					st.title("Informe sua base para an??lise:")
					uploaded_file = st.file_uploader("Fa??a o upload do seu CSV", type=["csv"])
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

							st.subheader("Probabilidade de Ataque ?? de {}%".format(result))

							if result >= 40.0 and result < 70.0:
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido maior que 40% mas menor que 70%, a sua rede PODE ter sofrido um ataque de nega????o de seriv??o.")
							elif result >= 70.0:
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido maior que 70%, a sua rede provavelmente SIM sofreu um ataque de nega????o de seriv??o.")
							elif result < 40.0:
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido menor que 40%, a sua rede provavelmente N??O sofreu um ataque de nega????o de seriv??o.")

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
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido maior que 40% mas menor que 70%, a sua rede PODE ter sofrido um ataque de nega????o de seriv??o.")
								st.write(result)
							elif result >= 70.0:
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido maior que 70%, a sua rede provavelmente SIM sofreu um ataque de nega????o de seriv??o.")
								st.write(result)
							elif result < 40.0:
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido menor que 40%, a sua rede provavelmente N??O sofreu um ataque de nega????o de seriv??o.")
								st.write(result)

							st.subheader("Probabilidade de Ataque ?? de {}%".format(result))
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
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido maior que 40% mas menor que 70%, a sua rede PODE ter sofrido um ataque de nega????o de seriv??o.")
								st.write(result)
							elif result >= 70.0:
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido maior que 70%, a sua rede provavelmente SIM sofreu um ataque de nega????o de seriv??o.")
								st.write(result)
							elif result < 40.0:
								st.warning("Em fun????o do ??ndice de comprometimento da sua coleta ter sido menor que 40%, a sua rede provavelmente N??O sofreu um ataque de nega????o de seriv??o.")
								st.write(result)

							st.subheader("Probabilidade de Ataque ?? de {} %".format(result))
						else:
							st.warning("Nenhum arquivo selecionado")

			else:
				st.warning("Usu??rio ou Senha Incorretos")
	elif choice == "Cadastro":
		new_username = st.text_input("Usu??rio")
		new_password = st.text_input("Senha", type='password')

		confirm_password = st.text_input("Confirme a Senha",type='password')
		if new_password == confirm_password:
			st.success("Senha Confirmada")
		else:
			st.warning("Senha n??o ?? a mesma")
		if st.button("Cadastrar"):
			create_usertable()
			hashed_new_password = generate_hashes(new_password)
			add_userdata(new_username, hashed_new_password)
			st.success("Conta Criada")
			st.info("Fa??a Login")

	elif choice == "Cr??ditos":
		st.header("Cr??ditos")

		st.subheader("Autores:")
		st.text("Davi Oliveira Rebou??as - Contato: davireboucas@alu.uern.br")
		st.text("Isaac de Lima Oliveira Filho (orientador) - Contato: issacoliveira@uern.br")

		st.subheader("Co-autores")
		st.text("Em??dio Lopes de Souza Neto - Contato: emidioneto@alu.uern.br")
		st.text("Jo??o Roberto de Ara??jo Mendes - Contato: joaomendes@alu.uern.br")

		st.subheader("Cr??ditos:")
		st.text("A base de dados utilizada nesta ferramenta foi desenvolvida pela University of New Brunswick \n em parceria com o Candadian Institute for Cybersecurity")
	else:
		pass

if __name__ == '__main__':
	main()