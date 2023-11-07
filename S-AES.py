from PyQt5 import QtCore, QtGui, QtWidgets
class S_AES:
    s_box = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7]
    ]

    def init(self):
        pass

    def add_round_key(self, state, round_key):
        for row in range(2):
            for col in range(2):
                state[row][col] ^= round_key[row][col]
                return state

    def byte_substitution(self, state):
        """半字节代替操作"""
        for row in range(2):
            for col in range(2):
                state[row][col] = self.s_box_lookup(state[row][col])
            return state

    def s_box_lookup(self, value):
        row = (value & 0xF0) >> 4
        col = value & 0x0F
        return self.s_box[row][col]

    def shift_rows(self, state):
        """行位移操作"""
        # 第一行不进行位移
        # 第二行向左循环位移1位
        state[1] = state[1][1:] + state[1][:1]
        # 第三行向左循环位移2位
        state[2] = state[2][2:] + state[2][:2]
        # 第四行向左循环位移3位
        state[3] = state[3][3:] + state[3][:3]
        return state
    
    def mix_columns(self, state):
        """列混淆操作"""
        new_state = [[0, 0], [0, 0]]
        MIX_COLUMNS_MATRIX = [
            [1, 4],
            [4, 1]
        ]
        for c in range(2):
            for r in range(2):
                new_state[r][c] = self.gf_mult(MIX_COLUMNS_MATRIX[r][0], state[0][c]) ^ self.gf_mult(MIX_COLUMNS_MATRIX[r][1], state[1][c])

        return new_state
    def gf_mult(self, a, b):
    # 有限域GF(2^4)上的乘法
        result = 0
        for _ in range(4):
            if b & 1:
                result ^= a
                a <<= 1
            if a & 0x10:
                a ^= 0x13
            b >>= 1
            return result
    def generate_round_keys(self, key):
        """生成轮密钥"""
        def sub_nib(nibble):
            if not (0 <= nibble < 16):
                raise ValueError(f"Invalid nibble value: {nibble}")
            return self.S_BOX[nibble >> 4][nibble & 0x3]

        def rot_nib(word):
            return [word[1], word[0]]

        def xor_words(word1, word2):
            return [x ^ y for x, y in zip(word1, word2)]

        w = [[key[0][0], key[0][1]], [key[1][0], key[1][1]]]

        round_keys = []

        RCON = [0x80, 0x30, 0x0C, 0x03, 0x00]
        for round_num in range(3):
            # 生成新的轮密钥
            round_key = [[0, 0], [0, 0]]

            # 计算 w2
            rot_w1 = rot_nib(w[1])
            w2_temp = [sub_nib(rot_w1[0]), sub_nib(rot_w1[1])]
            round_key[0] = xor_words(xor_words(w[0], RCON[round_num]), w2_temp)

            # 计算 w3
            round_key[1] = xor_words(round_key[0], w[1])

            # 将轮密钥添加到列表中
            round_keys.append(round_key)

            # 准备下一轮的 w
            w = [w[2], w[3]]

        return round_keys
    inv_s_box = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0xC, 0x0, 0x2, 0xE],
    [0x3, 0x4, 0x6, 0xD]
]
    def inverse_byte_substitution(self, state):
        """逆字节替换操作"""
        for row in range(2):
            for col in range(2):
             state[row][col] = self.inverse_s_box_lookup(state[row][col])
        return state

    def inverse_s_box_lookup(self, value):
        row = (value & 0xF0) >> 4
        col = value & 0x0F
        return self.inv_s_box[row][col]
    def inverse_shift_rows(self, state):
        """逆行移位操作"""
        # 第一行不进行位移

        # 第二行向右循环位移1位
        state[1] = state[1][-1:] + state[1][:-1]

        # 第三行向右循环位移2位
        state[2] = state[2][-2:] + state[2][:-2]

        # 第四行向右循环位移3位
        state[3] = state[3][-3:] + state[3][:-3]

        return state

    def inverse_mix_columns(self, state):
        """逆列混淆操作"""
        new_state = [[0, 0], [0, 0]]
        INV_MIX_COLUMNS_MATRIX = [
        [9, 2],
        [2, 9]
    ]
        for c in range(2):
            for r in range(2):
                new_state[r][c] = self.gf_mult(INV_MIX_COLUMNS_MATRIX[r][0], state[0][c]) ^ self.gf_mult(INV_MIX_COLUMNS_MATRIX[r][1], state[1][c])

        return new_state

    def encrypt(self, plaintext, key):
        state = plaintext

        # 轮密钥生成
        round_keys = self.generate_round_keys(key)

        # 初始化轮数和轮密钥索引
        round_num = 0
        round_key_index = 0

            # 执行9轮迭代操作
        while round_num < 9:
                # 密钥加操作
                state = self.add_round_key(state, round_keys[round_key_index])

                # 半字节代替操作
                state = self.byte_substitution(state)

                # 行移位操作
                state = self.shift_rows(state)

                # 列混淆操作（除了最后一轮）
                if round_num < 8:
                    state = self.mix_columns(state)

                # 更新轮数和轮密钥索引
                round_num += 1
                round_key_index += 1

            # 密钥加操作（最后一轮）
        state = self.add_round_key(state, round_keys[-1])

            # 返回加密后的密文
        return state
    def decrypt(self, ciphertext, key):
        state = ciphertext

            # 轮密钥生成（逆序）
        round_keys = self.generate_round_keys(key)[::-1]

            # 初始化轮数和轮密钥索引
        round_num = 0
        round_key_index = 0

            # 密钥加操作（最后一轮）
        state = self.add_round_key(state, round_keys[0])

            # 执行9轮逆向迭代操作
        while round_num < 9:
                # 逆向列混淆操作（除了最后一轮）
                if round_num < 8:
                    state = self.inverse_mix_columns(state)

                # 逆向行移位操作
                state = self.inverse_shift_rows(state)

                # 逆向半字节代替操作
                state = self.inverse_byte_substitution(state)

                # 密钥加操作
                state = self.add_round_key(state, round_keys[round_num])

                # 更新轮数和轮密钥索引
                round_num += 1
                round_key_index += 1

            # 返回解密后的明文
        return state
class Ui_MainWindow(object):
    def __init__(self):
        self.s_aes = S_AES()
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(370, 508)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(70, 70, 54, 16))
        self.label.setObjectName("label")
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(120, 70, 191, 20))
        self.lineEdit.setObjectName("lineEdit")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(70, 100, 54, 16))
        self.label_2.setObjectName("label_2")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_2.setGeometry(QtCore.QRect(120, 100, 191, 20))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(150, 140, 75, 24))
        self.pushButton.setObjectName("pushButton")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(50, 170, 54, 16))
        self.label_3.setObjectName("label_3")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_3.setGeometry(QtCore.QRect(120, 170, 191, 20))
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(70, 210, 54, 16))
        self.label_4.setObjectName("label_4")
        self.lineEdit_4 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_4.setGeometry(QtCore.QRect(120, 210, 191, 20))
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(70, 240, 54, 16))
        self.label_5.setObjectName("label_5")
        self.lineEdit_5 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_5.setGeometry(QtCore.QRect(120, 240, 191, 20))
        self.lineEdit_5.setObjectName("lineEdit_5")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(150, 280, 75, 24))
        self.pushButton_2.setObjectName("pushButton_2")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(50, 320, 54, 16))
        self.label_6.setObjectName("label_6")
        self.lineEdit_6 = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_6.setGeometry(QtCore.QRect(120, 320, 191, 20))
        self.lineEdit_6.setObjectName("lineEdit_6")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(30, 410, 75, 24))
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(140, 410, 75, 24))
        self.pushButton_4.setObjectName("pushButton_4")
        self.pushButton_5 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_5.setGeometry(QtCore.QRect(240, 410, 75, 24))
        self.pushButton_5.setObjectName("pushButton_5")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "明文："))
        self.label_2.setText(_translate("MainWindow", "密钥："))
        self.pushButton.setText(_translate("MainWindow", "加密"))
        self.label_3.setText(_translate("MainWindow", "加密结果："))
        self.label_4.setText(_translate("MainWindow", "密文："))
        self.label_5.setText(_translate("MainWindow", "密钥："))
        self.pushButton_2.setText(_translate("MainWindow", "解密"))
        self.label_6.setText(_translate("MainWindow", "解密结果："))
        self.pushButton_3.setText(_translate("MainWindow", "双重加密"))
        self.pushButton_4.setText(_translate("MainWindow", "遇到攻击"))
        self.pushButton_5.setText(_translate("MainWindow", "三重加密"))

        self.pushButton.clicked.connect(self.encrypt)
        self.pushButton_2.clicked.connect(self.decrypt)
        self.pushButton_3.clicked.connect(self.double_encrypt)
        self.pushButton_5.clicked.connect(self.triple_encrypt)

    def encrypt(self):
        plaintext = self.lineEdit.text()
        key = self.lineEdit_2.text()

        ciphertext = self.s_aes.encrypt(plaintext, key)

        self.lineEdit_3.setText(ciphertext)

        s_aes = S_AES()
        if len(plaintext) != 16 or len(key) != 16:
            QtWidgets.QMessageBox.warning(MainWindow, "输入错误", "输入的明文和密钥必须为16个十六进制字符")
            return

        plaintext_matrix = [[int(plaintext[i:i+2], 16) for i in range(0, 16, 2)]]
        key_matrix = [[int(key[i:i+2], 16) for i in range(0, 16, 2)]]

        ciphertext_matrix = s_aes.encrypt(plaintext_matrix, key_matrix)

        ciphertext = ''.join(f'{num:02x}' for sublist in ciphertext_matrix for num in sublist)

        self.lineEdit_3.setText(ciphertext)
    def decrypt(self):
        ciphertext = self.lineEdit_4.text()
        key = self.lineEdit_5.text()

        plaintext = self.s_aes.decrypt(ciphertext, key)

        self.lineEdit_6.setText(plaintext)

        s_aes = S_AES()
        if len(ciphertext) != 16 or len(key) != 16:
            QtWidgets.QMessageBox.warning(MainWindow, "输入错误", "输入的密文和密钥必须为16个十六进制字符")
            return

        ciphertext_matrix = [[int(ciphertext[i:i+2], 16) for i in range(0, 16, 2)]]
        key_matrix = [[int(key[i:i+2], 16) for i in range(0, 16, 2)]]

        plaintext_matrix = s_aes.decrypt(ciphertext_matrix, key_matrix)

        plaintext = ''.join(f'{num:02x}' for sublist in plaintext_matrix for num in sublist)

        self.lineEdit_6.setText(plaintext)
    # 双重加密示例
    def double_encrypt(self):
        plaintext = self.lineEdit.text()
        key = self.lineEdit_2.text()

        ciphertext = self.s_aes.encrypt(plaintext, key)
        double_ciphertext = self.s_aes.encrypt(ciphertext, key)

        self.lineEdit_3.setText(double_ciphertext)

    # 三重加密示例
    def triple_encrypt(self):
        plaintext = self.lineEdit.text()
        key = self.lineEdit_2.text()

        ciphertext = self.s_aes.encrypt(plaintext, key)
        double_ciphertext = self.s_aes.encrypt(ciphertext, key)
        triple_ciphertext = self.s_aes.encrypt(double_ciphertext, key)

        self.lineEdit_3.setText(triple_ciphertext)
app = QtWidgets.QApplication([])
MainWindow = QtWidgets.QMainWindow()
ui = Ui_MainWindow()
ui.setupUi(MainWindow)
MainWindow.show()
app.exec_()