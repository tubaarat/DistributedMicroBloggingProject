# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'openning_window.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_openning_window(object):
    def setupUi(self, openning_window):
        openning_window.setObjectName("openning_window")
        openning_window.resize(618, 334)
        self.centralWidget = QtWidgets.QWidget(openning_window)
        self.centralWidget.setObjectName("centralWidget")
        self.et_ip = QtWidgets.QTextEdit(self.centralWidget)
        self.et_ip.setGeometry(QtCore.QRect(240, 50, 351, 31))
        self.et_ip.setObjectName("et_ip")
        self.et_port = QtWidgets.QTextEdit(self.centralWidget)
        self.et_port.setGeometry(QtCore.QRect(240, 90, 351, 31))
        self.et_port.setObjectName("et_port")
        self.et_c_port = QtWidgets.QTextEdit(self.centralWidget)
        self.et_c_port.setGeometry(QtCore.QRect(240, 170, 351, 31))
        self.et_c_port.setObjectName("et_c_port")
        self.et_c_ip = QtWidgets.QTextEdit(self.centralWidget)
        self.et_c_ip.setGeometry(QtCore.QRect(240, 130, 351, 31))
        self.et_c_ip.setObjectName("et_c_ip")
        self.label = QtWidgets.QLabel(self.centralWidget)
        self.label.setGeometry(QtCore.QRect(70, 60, 151, 16))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralWidget)
        self.label_2.setGeometry(QtCore.QRect(70, 100, 161, 16))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralWidget)
        self.label_3.setGeometry(QtCore.QRect(70, 180, 161, 16))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralWidget)
        self.label_4.setGeometry(QtCore.QRect(70, 140, 151, 16))
        self.label_4.setObjectName("label_4")
        self.btn_connect = QtWidgets.QPushButton(self.centralWidget)
        self.btn_connect.setGeometry(QtCore.QRect(450, 260, 114, 32))
        self.btn_connect.setObjectName("btn_connect")
        openning_window.setCentralWidget(self.centralWidget)

        self.retranslateUi(openning_window)
        QtCore.QMetaObject.connectSlotsByName(openning_window)

    def retranslateUi(self, openning_window):
        _translate = QtCore.QCoreApplication.translate
        openning_window.setWindowTitle(_translate("openning_window", "openning_window"))
        self.label.setText(_translate("openning_window", "IP Adresiniz:"))
        self.label_2.setText(_translate("openning_window", "Port Numaranız:"))
        self.label_3.setText(_translate("openning_window", "Bağlantı Port Adresi:"))
        self.label_4.setText(_translate("openning_window", "Bağlantı IP Adresi:"))
        self.btn_connect.setText(_translate("openning_window", "Bağlan"))

