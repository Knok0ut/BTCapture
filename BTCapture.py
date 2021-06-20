import sys
from ui import MainWindow, SavePacketsDialog, OpenDocumentDialog, BlackListDialog
from PyQt6.QtWidgets import QApplication, QMainWindow, QHeaderView, QTableWidgetItem, QTreeWidgetItem, QMessageBox, \
    QDialog, QListWidgetItem, QWidget, QAbstractItemView,,QDialog, QListWidgetItem, QFileDialog, QMenu
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QPoint, QModelIndex
from PyQt6 import QtCore
from PyQt6.QtGui import QAction, QCursor
from ui.HexView import HexView
import pymongo
import gridfs
import time
import threading
import datetime
import pickle
from ui import StatisticsDialog, TrackerWindow, DHTWindow, BTWindow
from util.dht import *
from util.tracker import *
from util.bittorrent import *
from util.Log import getlogger
from util.BlackList import BlackList
import qbittorrentapi

client = pymongo.MongoClient('mongodb://localhost:27017')
db = client["BTCapture"]
c_set = db["PacketDict"]
fs = gridfs.GridFS(db, "PacketDict")
logger = getlogger()
logger.info("app opened")
bclient = qbittorrentapi.Client(host='localhost:8080', username='admin', password='adminadmin')
typedict = {-3: 'Bittorrent', -2: 'Continuation Data', -1: 'Handshake',
            0: 'Choke', 1: 'Unchoke', 2: 'Interested', 3:'Not Interested',
            4: 'Have', 5: 'Bitfield', 6: 'Request', 7:'Piece', 8: 'Cancel',
            9: 'Port', 13: 'Suggest Piece', 14: 'Have All', 15: 'Have None',
            16: 'Reject Request', 17: 'Allowed Fast', 20: 'Extended'}


class Capture(QThread):
    signal = pyqtSignal(Packet)

    def __init__(self):
        super(Capture, self).__init__()
        self.cap = None
        self.filter = "http or bt-dht or bittorrent"

    def run(self):
        # print(self.filter)
        if not self.filter:
            # self.cap = pyshark.LiveCapture(interface="WLAN", use_json=True, include_raw=True,
            #                                display_filter="bittorrent")
            self.cap = pyshark.LiveCapture(interface="WLAN", display_filter="bittorrent")
        if self.filter:
            logger.debug("current filter: " + str(self.filter))
        if not self.filter:
            # self.cap = pyshark.LiveCapture(interface="WLAN", use_json=True, include_raw=True,
            #                                display_filter="bittorrent")
            self.cap = pyshark.LiveCapture(interface="WLAN",
                                           display_filter="http or bt-dht or bittorrent",
                                           decode_as={'udp.port == 51934': 'bt-dht'})
        else:
            # self.cap = pyshark.LiveCapture(interface="WLAN", use_json=True, include_raw=True, display_filter=self.filter
            #                                )
            self.cap = pyshark.LiveCapture(interface="WLAN", display_filter=self.filter)
        self.cap.apply_on_packets(self.send_signal, timeout=300)

    def stop(self):
        self.terminate()
        self.wait()

    def send_signal(self, pkt: Packet):
        # print("I'm not terminated")
        self.signal.emit(pkt)

    def get_id(self):
        return threading.get_ident()


class Window(QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        self.trackeranalyse = None
        self.dhtanalyse = None
        self.bittorrentanalyse = None
        self.bl = BlackList()
        self.pkt_dict = dict()
        self.ui = MainWindow.Ui_MainWindow()
        self.ui.setupUi(self)
        self.hex_view = HexView()
        self.hex_view.setParent(self.ui.splitter)
        self.filter = self.ui.lineEdit
        self.filter.textChanged.connect(self.set_placeholder_font)
        self.go_btn = self.ui.goBtn
        self.go_btn.clicked.connect(self.do_filter)
        self.ui.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.ui.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.table = self.ui.tableWidget
        self.tree = self.ui.treeWidget
        self.menu = self.ui.menu
        self.capture_init()
        self.table_init()
        self.tree_init()
        self.ui.actionstart.triggered.connect(self.start)
        self.ui.actionstop.triggered.connect(self.stop)
        self.ui.actionstop.setEnabled(False)
        self.ui.actionsaveToDB.triggered.connect(self.save_to_db)
        self.ui.actionsaveToDB.setEnabled(False)
        self.ui.actionrestoreFromDB.triggered.connect(self.restore_from_db)
        self.ui.actionrestoreFromDB.setEnabled(True)
        self.ui.actionanalyse.setEnabled(False)
        self.ui.actionanalyse.triggered.connect(self.analyse)
        self.ui.actionclear.triggered.connect(self.clear_all_info)
        self.ui.actionclear.setEnabled(False)
        self.ui.actionnewTorrentJob.triggered.connect(self.start_new_job)
        self.ui.actionblackList.triggered.connect(self.black_list)
        self.is_running = False
        self.time = None
        self.current_pkt = None
        # self.inMemCapture = pyshark.InMemCapture()
        self.last_filter_is_empty = True
        self.set_placeholder_font()

    def set_placeholder_font(self):
        if self.filter.text().strip() == "":
            self.last_filter_is_empty = True
            # self.filter.palette().setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.red)
            self.filter.setStyleSheet('''
                QLineEdit {
                    color: grey;
                }
                ''')
            self.filter.setPlaceholderText(f"current filter: {self.capture.filter}")
        else:
            # self.filter.setStyleSheet("color: black")
            if self.last_filter_is_empty:
                self.last_filter_is_empty = False
                # self.filter.palette().setColor(QPalette.ColorRole.Text, Qt.GlobalColor.black)
                self.filter.setStyleSheet('''
                                QLineEdit {
                                    color: black;
                                }
                                ''')

    def capture_init(self):
        self.capture = Capture()
        self.capture.signal.connect(self.deal_with_pkt)

    def table_init(self):
        self.table.setRowCount(0)
        self.table.cellClicked.connect(self.show_detail)

    def tree_init(self):
        self.tree.setColumnCount(1)
        self.tree.setHeaderHidden(True)

    def start(self):
        self.trackeranalyse = TrackerAnalyse()
        self.dhtanalyse = DHTAnalyse()
        self.bittorrentanalyse = BittorrentAnalyse()
        self.clear_all_info()
        self.current_pkt = None
        if self.pkt_dict:
            del self.pkt_dict
        self.pkt_dict = dict()
        self.table.setRowCount(0)
        self.capture.start()
        self.time = time.time()
        self.is_running = True
        self.ui.actionstart.setEnabled(False)
        self.ui.actionstop.setEnabled(True)
        self.ui.actionsaveToDB.setEnabled(False)
        self.ui.actionrestoreFromDB.setEnabled(False)
        self.ui.actionanalyse.setEnabled(False)
        self.ui.actionclear.setEnabled(False)
        logger.info("capture started")

    def stop(self):
        if self.capture.isRunning():
            self.capture.stop()
        self.is_running = False
        self.capture_init()
        self.ui.actionstart.setEnabled(True)
        self.ui.actionstop.setEnabled(False)
        self.ui.actionsaveToDB.setEnabled(True)
        self.ui.actionrestoreFromDB.setEnabled(True)
        self.ui.actionanalyse.setEnabled(True)
        self.ui.actionclear.setEnabled(True)
        logger.info("capture stopped")

    def add_row(self, ls: list):
        row_cnt = self.table.rowCount()
        tmp = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.insertRow(row_cnt)
        for idx, item in enumerate(ls):
            i = QTableWidgetItem()
            i.setData(Qt.ItemDataRole.DisplayRole, item)
            self.table.setItem(row_cnt, idx, i)
        self.table.setSortingEnabled(tmp)

    def deal_with_pkt(self, pkt: Packet):
        self.pkt_dict[int(pkt.number)] = pkt
        ip = gethostip()
        ipv6 = gethostipv6()
        if hasattr(pkt, "ip"):
            if str(pkt.ip.src) == ip:
                pkt.send = True
                pkt.recv = False
            elif str(pkt.ip.dst) == ip:
                pkt.send = False
                pkt.recv = True
        elif hasattr(pkt, "ipv6"):
            if str(pkt.ipv6.src) in ipv6:
                pkt.send = True
                pkt.recv = False
            elif str(pkt.ipv6.dst) in ipv6:
                pkt.send = False
                pkt.recv = True
        if hasattr(pkt, "http"):
            info = print_tracker_info(pkt, self.trackeranalyse)
        if hasattr(pkt, "bt-dht"):
            info = print_dht_info(pkt, self.dhtanalyse)
        if hasattr(pkt, "bittorrent"):
            info = print_bittorrent_info(pkt, self.bittorrentanalyse)
        if hasattr(pkt, "ip"):
            if hasattr(pkt, "http") or hasattr(pkt, "bt-dht") or hasattr(pkt, "bittorrent"):
                if info and info != "ICMP":
                    self.add_row(
                        [int(pkt.number), "{:.6f}".format(float(pkt.sniff_timestamp) - self.time), str(pkt.ip.src),
                         str(pkt.ip.dst),
                         pkt.highest_layer.split("_RAW")[0], int(pkt.length), info])
                else:
                    pass
            else:
                self.add_row(
                    [int(pkt.number), "{:.6f}".format(float(pkt.sniff_timestamp) - self.time), str(pkt.ip.src),
                     str(pkt.ip.dst),
                     pkt.highest_layer.split("_RAW")[0], int(pkt.length), pkt.frame_info])
        elif hasattr(pkt, "ipv6"):
            if hasattr(pkt, "http") or hasattr(pkt, "bt-dht") or hasattr(pkt, "bittorrent"):
                if info and info != "ICMP":
                    self.add_row(
                        [int(pkt.number), "{:.6f}".format(float(pkt.sniff_timestamp) - self.time), str(pkt.ipv6.src),
                         str(pkt.ipv6.dst),
                         pkt.highest_layer.split("_RAW")[0], int(pkt.length), info])
                else:
                    pass
            else:
                self.add_row(
                    [int(pkt.number), "{:.6f}".format(float(pkt.sniff_timestamp) - self.time), str(pkt.ipv6.src),
                     str(pkt.ipv6.dst),
                     pkt.highest_layer.split("_RAW")[0], int(pkt.length), pkt.frame_info])
        else:
            print("no attribute ip/ipv6")

    def save_to_db(self):
        self.save_dialog = QDialog()
        self.save_dialog.ui = SavePacketsDialog.Ui_Dialog()
        self.save_dialog.ui.setupUi(self.save_dialog)
        self.save_dialog.ui.pushButton.clicked.connect(self._save_to_db)
        self.save_dialog.show()

        # with open("./tmp/this.dump", "wb") as f:

    def _save_to_db(self):
        name = self.save_dialog.ui.lineEdit.text()
        name = name.strip()
        if name == "":
            name = str(datetime.datetime.now()).replace(" ", ":").replace(".", ":").strip()
            self.info(f"输入为空,使用默认名称: {name}", self.save_dialog)
        if fs.exists(name.strip()):
            self.warn("命名冲突，该存档已经存在", self.save_dialog)
            return
        data = pickle.dumps(self.pkt_dict)
        fs.put(data, _id=name, filename=name)
        self.save_dialog.close()
        self.info("保存成功")
        logger.info(f"save current packets to data base, document name: {name}")

    def restore_from_db(self):
        self.trackeranalyse = TrackerAnalyse()
        self.dhtanalyse = DHTAnalyse()
        self.bittorrentanalyse = BittorrentAnalyse()
        self.restore_dialog = QDialog()
        self.restore_dialog.ui = OpenDocumentDialog.Ui_Dialog()
        self.restore_dialog.ui.setupUi(self.restore_dialog)
        self.restore_dialog.ui.pushButton.clicked.connect(self._restore_from_db)
        self.restore_dialog.ui.listWidget.doubleClicked.connect(self._restore_from_db)
        self.restore_dialog.show()
        ls = fs.list()
        for item in ls:
            self.restore_dialog.ui.listWidget.addItem(QListWidgetItem(item))
        self.ui.actionanalyse.setEnabled(True)

    def _restore_from_db(self):
        if self.is_running:
            self.stop()
        self.clear_all_info()
        name = self.restore_dialog.ui.listWidget.currentItem().text().strip()
        d = pickle.loads(fs.get(name).read())
        if not d:
            self.restore_dialog.close()
            self.warn("这个存档没有任何记录")
        # self.pkt_dict: dict = self.pkt_dict
        else:
            self.pkt_dict = d
            keys = list(self.pkt_dict.keys())
            keys.sort()
            for key in keys:
                self.deal_with_pkt(self.pkt_dict[key])
            self.restore_dialog.close()
        self.ui.actionrestoreFromDB.setEnabled(True)
        self.ui.actionclear.setEnabled(True)
        self.ui.actionsaveToDB.setEnabled(True)
        logger.info(f"restore packets from data base, document name: {name}")

    def black_list(self):
        self.black_list_dialog = QDialog()
        self.black_list_dialog.ui = BlackListDialog.Ui_Dialog()
        self.black_list_dialog.ui.setupUi(self.black_list_dialog)
        self.black_list_dialog.ui.add.clicked.connect(self._add_black_list)
        self.black_list_dialog.ui.search.clicked.connect(self._search_black_list)
        self.black_list_dialog.ui.refreshFromServer.clicked.connect(self._refresh_black_list)
        self.black_list_dialog.ui.listWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.black_list_dialog.ui.listWidget.customContextMenuRequested[QPoint].connect(self._list_menu)
        self._show_black_list()
        self.black_list_dialog.show()

    # def eventFilter(self, source, event):
    #     if event.type() == QtCore.QEvent.Type.ContextMenu and self.black_list_dialog is not None and \
    #             self.black_list_dialog.ui is not None and source is self.black_list_dialog.ui.listWidget:
    #         menu = QMenu()
    #         action = QAction()
    #         action.setObjectName(u"删除")
    #         action.triggered.connect(self._del_black_list)
    #         menu.addAction(action)
    #         menu.exec(event.globalPos())
    #         return True
    #     else:
    #         return super().eventFilter(source, event)

    def _search_black_list(self):
        pass

    def _list_menu(self, pos):
        menu = QMenu(self.black_list_dialog)
        action = QAction(self.black_list_dialog)
        action.setObjectName("delete")
        action.setText("删除")
        menu.addAction(action)
        action.triggered.connect(self._del_black_list)
        menu.show()
        menu.exec(QCursor.pos())

    # menu.exec(QCursor.pos())

    def _add_black_list(self):
        text = self.black_list_dialog.ui.lineEdit.text()
        text = text.strip()
        if text != "":
            self.bl.add(text)
            self._show_black_list()
        else:
            self.warn("输入框没有任何输入")

    def _del_black_list(self):
        text = self.black_list_dialog.ui.listWidget.currentItem().text().strip()
        # index = self.black_list_dialog.ui.listWidget.indexAt(QCursor.pos()).column()
        # if index > -1:
        #     text = self.black_list_dialog.ui.listWidget.item(index).text()
            # self._del_black_list(text)
        self.bl.remove(text)
        self._show_black_list()

    def _refresh_black_list(self):
        self.bl.refresh_from_server()
        self._show_black_list()

    def _show_black_list(self):
        self.black_list_dialog.ui.listWidget.clear()
        ls = self.bl.get_black_list()
        if ls:
            for item in ls:
                self.black_list_dialog.ui.listWidget.addItem(QListWidgetItem(item))

    def analyse(self):
        self.analysedialog = QWidget()
        self.analysedialog.ui = StatisticsDialog.Ui_Dialog()
        self.analysedialog.ui.setupUi(self.analysedialog)
        self.analysedialog.ui.Tracker.clicked.connect(self._tracker_info)
        self.analysedialog.ui.DHT.clicked.connect(self._dht_info)
        self.analysedialog.ui.BT.clicked.connect(self._bt_info)
        self.analysedialog.show()

    def _tracker_info(self):
        self.trackerwindow = QWidget()
        self.trackerwindow.ui = TrackerWindow.Ui_Form()
        self.trackerwindow.ui.setupUi(self.trackerwindow)

        table = self.trackerwindow.ui.tracker_ipport
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for key in self.trackeranalyse.tracker_ipport.keys():
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem("(%s,%s)" % (key[0], key[1])))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(self.trackeranalyse.tracker_ipport[key])))
            row_cnt += 1

        table = self.trackerwindow.ui.localport
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for key in self.trackeranalyse.local_port.keys():
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem(str(key)))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(self.trackeranalyse.local_port[key])))
            row_cnt += 1

        table = self.trackerwindow.ui.type_num
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for key in self.trackeranalyse.type.keys():
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem(str(key)))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(self.trackeranalyse.type[key])))
            row_cnt += 1

        table = self.trackerwindow.ui.peers
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for item in self.trackeranalyse.peers:
            temp = item.split(":")
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem(str(temp[0])))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(temp[1])))
            row_cnt += 1
        self.trackerwindow.showMaximized()
        self.trackerwindow.show()
        logger.info("analyse Tracker")


    def _dht_info(self):
        self.dhtwindow = QWidget()
        self.dhtwindow.ui = DHTWindow.Ui_Form()
        self.dhtwindow.ui.setupUi(self.dhtwindow)

        table = self.dhtwindow.ui.ipport
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for key in self.dhtanalyse.requested_ipport:
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem("(%s,%s)" % (key[0], key[1])))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(self.dhtanalyse.requested_ipport[key])))
            row_cnt += 1

        table = self.dhtwindow.ui.nodes
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for item in self.dhtanalyse.nodes:
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem(str(item[0])))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(item[1])))
            table.setItem(row_cnt, 2, QTableWidgetItem(str(item[2])))
            row_cnt += 1

        table = self.dhtwindow.ui.peers
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for item in self.dhtanalyse.peers:
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem(str(item[0])))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(item[1])))
            row_cnt += 1

        table = self.dhtwindow.ui.type_num
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for key in self.dhtanalyse.type.keys():
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem(str(key)))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(self.dhtanalyse.type[key])))
            row_cnt += 1

        self.dhtwindow.showMaximized()
        self.dhtwindow.show()
        logger.info("analyse DHT")

    def _bt_info(self):
        self.btwindow = QWidget()
        self.btwindow.ui = BTWindow.Ui_Form()
        self.btwindow.ui.setupUi(self.btwindow)

        table = self.btwindow.ui.localport
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for key in self.bittorrentanalyse.localport.keys():
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem(str(key)))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(self.bittorrentanalyse.localport[key])))
            row_cnt += 1

        table = self.btwindow.ui.remote_ipport
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        for key in self.bittorrentanalyse.remote_ipport.keys():
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem("(%s,%s)" % (str(key[0]), str(key[1]))))
            table.setItem(row_cnt, 1, QTableWidgetItem(str(self.bittorrentanalyse.remote_ipport[key])))
            row_cnt += 1

        table = self.btwindow.ui.up_down
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        table.insertRow(0)
        table.setItem(0, 0, QTableWidgetItem("up"))
        table.setItem(0, 1, QTableWidgetItem(str(self.bittorrentanalyse.up)))
        table.insertRow(1)
        table.setItem(1, 0, QTableWidgetItem("down"))
        table.setItem(1, 1, QTableWidgetItem(str(self.bittorrentanalyse.down)))

        table = self.btwindow.ui.type_num
        table.setSortingEnabled(True)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        row_cnt = 0
        keys = self.bittorrentanalyse.type.keys()
        keys = sorted(keys)
        for key in keys:
            table.insertRow(row_cnt)
            table.setItem(row_cnt, 0, QTableWidgetItem(str(key)))
            if key in typedict.keys():
                table.setItem(row_cnt, 1, QTableWidgetItem(typedict[key]))
            else:
                table.setItem(row_cnt, 1, QTableWidgetItem('Unknown'))
            table.setItem(row_cnt, 2, QTableWidgetItem(str(self.bittorrentanalyse.type[key])))
            row_cnt += 1

        self.btwindow.showMaximized()
        self.btwindow.show()
        logger.info("analyse BT")

    def clear_all_info(self):
        self.pkt_dict = dict()
        self.tree.clear()
        self.table.setRowCount(0)
        self.time = 0

    def show_detail(self, row, column):
        item = self.table.item(row, 0)
        pkt: Packet = self.pkt_dict.get(int(item.text()))
        self.current_pkt = pkt
        if not pkt:
            logger.error("packet map error")
            return
        # c = pyshark.InMemCapture()
        # tmp_pkt = c.parse_packet(pkt.get_raw_packet())
        self.show_pkt_tree(pkt)
        if hasattr(pkt, "data") and hasattr(pkt.data, "data"):
            self.hex_view.generateView(bytes.fromhex(pkt.data.data))
        else:
            self.hex_view.generateView(b"")

    def show_pkt_tree(self, pkt: Packet):
        self.tree.clear()
        layers: list = pkt.layers
        for l in layers:
            if str(l.layer_name).endswith("_raw"):
                continue
            if l.layer_name == l.DATA_LAYER:
                b = QTreeWidgetItem(self.tree)
                b.setText(0, "DATA")
                break
            b = QTreeWidgetItem(self.tree)
            b.setText(0, l.layer_name)
            for field_line in l._get_all_field_lines():
                field_line = field_line.strip()
                if field_line.split(":")[0].endswith("_raw"):
                    continue
                child = QTreeWidgetItem(b)
                child.setText(0, field_line)

    def do_filter(self):
        if self.capture and self.capture.isRunning():
            self.capture.exit(0)
        if not self.capture:
            self.capture = Capture()
        f = self.filter.text()
        logger.info(f"set filter to: {f}")
        self.capture.filter = f
        self.start()

    def _select_file(self):
        file_path = QFileDialog.getOpenFileName(self, "", os.getcwd())
        print(file_path)
        return file_path

    def start_new_job(self):
        self.stop()
        self.start()
        file_path = self._select_file()
        if "ok" in bclient.torrents.add(file_path).lower():
            self.info("成功下载任务，开始重新捕获数据包")

    def warn(self, msg: str, parent=None, title=""):
        if not parent:
            QMessageBox.warning(self, title, msg)
        else:
            QMessageBox.warning(parent, title, msg)

    def info(self, msg: str, parent=None, title=""):
        if not parent:
            QMessageBox.information(self, title, msg)
        else:
            QMessageBox.information(parent, title, msg)

    def closeEvent(self, event):
        logger.info("app closed")
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec())

# handshake
# b'Xil\xa5\xe2\xd3\x00(\xf8\xf4pY\x08\x00E\x00\x00ln\xd8@\x00\x80\x06\x83\x1f\xac\x14\x97\x04\xb4\x8a\x10\xf1\x06%o\xad\x9d\x83\x1dP\xb9Yt\x07P\x18\x02\x04\tl\x00\x00\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x05\xaa\xc7\xa3i\xd6\xdd\xa2\x11[\xc0\xd1\x88\xa5\xbc\x91A\xd2cvs-UT355S-n\xafFPlBh5\x06\x8eSZ'
# ...

# b'Xil\xa5\xe2\xd3\x00(\xf8\xf4pY\x08\x00E\x00\x05\x92\x97\x8e@\x00\x80\x06\x9e\xe9\xac\x14\x97\x04r(\t\xad.\xb5\'O\xbd\xb6>y\x9f]\xc5\x84P\x18\x01\x00\xabL\x00\x00\xe6ky\xf4=W:\x0f\x9a\xe2+\x88\x90{\xc2\x02\x93\x1b\x9e$\xc5\xa9\xb5<WA\xa6\xe4\xe8/,S\xa5\x16\xdc\x9a\x02\xb2*\xe3\x83f\xfcY\xe862\xf1\xdd\x896\xbc5\xa0\xabF\x05ag&sbL\xf6\xccN\xa1(\xb0\x01,|"%\x11 \t\x9e\\\xd6\x85v\xd8\x82\xbb\xd0b\xe7\xa2l\x9e\xec\xf9_z\x98 \xad\x14\x1e\x1c_eW2\xf82\x14\xfd\x85\x1d\x9c\xe7\xf4\x93M\xb6<\xb9\xa2\x8c\t\xfa\xc0_\n<v\x03m\xd6\xaf\xa9\xcci\xdc*\xf5W\x0c\xf7\xdfh\xc7\x9e\xa0.\xb5\x95\x11\xb3\xcf\x8a`\xe2hyi6\xdd\xc4\xf6M\xcd\x9e\r<o\x8d\xff\xfa\x9f\x98;\xa7\xa8JG\x97\xb5\xb1\x17\xaeM\xb0\x88p\xd8\x96\x94\xcc\xda\x89\x9d\x03a\x88c\xd5\xff4\x83\xb9%~q\x0ct\x1c\x19\xff\x83\x08\xdf\rV\xe5\r\x97F\xdd\x9a\xa5\xc5\xdb[\t\xf0\x93\x02\x05[\xb5;)\x04\x0f\xa3W\xe7\xf0^\xcc\x8e}\\*\xc6\xd9\x19aX\xbd\xc6n\xee\x11e\xd2\xb8w\xf6\x90\x08\xa3|#.W\xe3\x82\x80\x14\xc7\xecr\x99J\x9e\xb6\xbf?\xe3\x08\xd3\x8fOl\x84]\xc8\xdf0G0T\xcc\\\xdf\xefO\xfd\xae\';\xe2\x0482\x94\xc5\xd2g\xe4\xb7\x12\xf9\xe0f\xa8\x92A\rf:\x16\x173\xb7.\x00#\x17[Q5f\x9d\x9dq\x81v\xd9\xab\x7f\x12\xbf\xc8\xfa\x93sZ@\xf0\xc4H\x9d\xf8 r\x14\xee>\x7f\x8b\xc2\xa9\xba\xfb\x06\x01\xec\xd3\xfdXO\xef%9\xf2x\xc8\xf4\x1c\'\xadmi\xac\xad\xddy\x8d\x19\xdd\x9b\xe6\x88\x12z\xd1s\xf3\xe8\xa0\x18\xdag\xff\xcb\x9bLX\xf8t9K\xb2\x06\x84b\xba\xacPnHb\xf4k\xe6\x91\xad\x91\x82]\xbb\xeb\xf2\xef\xaf\xe4\x16<\x9c=\xd1\xfe\xe4\xa9A\x8b\x97\xf2\xeb\xa97\x0c\x11\r\xae\xe7\x8ae\x9b\xf9\xd3,\x7f\x852 \x18\xd5\xd1\xef\xe6\xe4?s\x04\xc3TgKW\xc4\x9a!\x9f\xbf3j\x17\xb7\xe7\xbb\xd0\xbelC\x1c\xf6fZ})A\x17\xa4\xb0NO\xc5\x13\x8e\xf4\x1a:\x11\xeb\xe0\xd0\xb8\xb9D\xd9\xab\x85\x86F\x9e\x03\x07j\xf8\xef\x9d\xfdgH\xe3\\u\xd6\xc4\xc9\xff\x8f\x9f^@\xe3\x07\xf0\x03=\x86\xa4\x9c\xd3\xcd\x90z\xa9K\xd8\xdb\x9aD\x8c\x10d\x89\x0f\r\x9b\x08\'\x9cFL\xa4U\x14\xde-\x15@\x10\xf1D\xfdTY!\x98\x01@Pk\xfed%\xdb\xc3\x88dY\x1bT\x0f\x90\xe7a4\xeaa\xfdG\x8f\n\xec[V]\x975\x93\xa05\xab~\xd2\x06\xb6.\xc7\x8c\x14\x02[C\xaf\xe94~\x1a\x1ev{\tyi\x1eT\xfb\xaa\x1b\xc8\x18k#$\x8a\xcf\x02\x8c\x13\x98\x16\xd9ZtV\xfbw"\x95l\xe1\t\xa0\x07\xc41\xa8\xcd\x11n\xe54\xe9<\xa5]R\xa6y\x1b\x92\xc1\x956\xd4D\xbb\xfd\xeeT\xce\xd2Z\xbcl\xce&t\xb9A\x91\xea\xf0\xb3\xe0\xb1\x99R\tJ\x9e\xa4\xcb\x86U\x8dr0\x0c\xc2\x94\x0ed\xf8r/m\xd9\xc7\xa4{T\x94\xcd\xb9\xfb&\xfb\xeaj\x96\xee\x91\xb5\xec\xb7\x8d!;\x18\xe9RMr\xf0\x0b\xee6\xcby}\xc2\xee\xe1\x13\xb1\xab>\xc2\x07\xfa7\xbe\xb3\xd2\x10\xdd\x86\x93D8\xeb\xd8u\xa1\x16SSr\x89Z,\xba\x96\x89\x02\x9fJ1\xcd\x85\xb4\xb2\xb5\xd1b\x89\x18\xe7\xb1\x95\x1bj|K\xef\xfc\xdeT\x0e\x1a\xa7gjbm\xc3[\xa0\xa0\xb5A"S\x01\x02\x0b\xd3\xf0\xc2\xaf\xee\xca\xb2V\xf6EYu(h\x02qP\'"\xd6\xe9<\x05fO9\xa9\x03\x05\x85r]\xc6l\x0f\xe2\xe1\xa2\x8e\x14\xd2 ]\\5\xc7M\xe60\xfd\xb3\tT\xb95\xaa>=l\x92\x00\x00@\t\x07\x00\x00\x02\xe3\x00\x00\x80\x00\xbf9\xba\x1eZ\xfec09:\x07\x1a\xc5>\xbd8?\x04|9\x80\xcah\xae\n\xf0w\xb8\x8b\xa9{u\xc4N\xafb|"\xb0\x0e\xea\x1a\x01i\x06\xec\xe1\x01\xeb\xf7\x06)\xb2\x11Y\xa7\x00\xa4\x8e|\x002ta\xa7d\x03\xd7l\r\x96\x1a\xb9\xe4\x1c\xe8\r\x91J\xf3\xe5\xfd\xf2\xe4\x9a\xac\x01rg\x93\xcd\xb2h\r\xacS\x18-\xa37,\'<\xf0\x1f\\Y\xfd ,\xe1\xe9\xd8mL\x8f\xa2\x1cX\xb9\xe7H\x16\xd7\x11\x9b"\xb1F\xe3\xe8\xfb]Y\xc4\x89sC\x1dgm\x87\x05\xea\xf7\x9c\xe5x\xa2+\xec5\x14\x8b\xf3\xae0\xda\xe7\xb5\xdeg\x81\xf2m\xe3[\xe7S>i\xe9+\xe0\x18\x86\x10\xc7\xfb\xae\xa2\xcd]X\xdc\x0e\xd00[\x90XN\x91\xa8P\xa4H\xa03\xde\'(\xc4a\x9d\xb0V\xae\xd3\xca\xfe\xe9\xa4f\xd6\x0e\x02\x88\'|5R\x8b\x93Z\xc5\xe6\x92|:b\'\x1a\xb0\xa0\xeez\xe4\xf7\xf5JC\xd7\x15<\xde\xffi\x88\x8cN\xf2^\x8c\x15\xfe\x08\xc1\xd3\x1a\x95!\x89<q\xa6\x15rv$\xb2\xf3\xee\x15\xe0y\x0f\xaeD\x84\x9bz\xb3O\xac\xa0\x97\xc5\xb5=l\x8a\x0cH\xbd@\xc79I\x87\x1d\xfc\xf7\x01c\xe5&\x9aG\xe2\x97\xb0\xc2\xd5\x8f-\xa5\xfe2\x81\xba\xe6:\x16\xc5ZX\xfd\xdb\xd8\xf6D\x03\x9d;\x9e\xf5s\x96iu\xe74\x87\xe1{\x18\x84CN\xe5\x8a.\x99\xfe\x97\xd2&\xf2LI\xbc\xc8(\x85\xda\xd5i\xa7\xffrN\r\xcd&\xea3:\xa2I\xa1\xb9\xe2*0\x90\xb4\xecY\xf8\x8c\x80\xc7\x1e\xf8\xfe\xd7H\xf2(\x86\x11]l4\x0b\x85\xa1\xef\x83\r\xef\xf3\xae\xfev;\xfc\xb7O]\x88\x1bs.\xae\x1c\xa3\xdd\xf5\xbf\x92\x14d\xf9?\x14\x1b}\xcd\x87\xa2\xd1[\x0b\xde\x85 \xdbJ`\x8c1\x8fsX\xf1'
