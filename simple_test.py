import sys
import pyshark
from pyshark.packet.packet import Packet
from pyshark.packet.layer import Layer
from ui import mainwindow
from PyQt6 import QtCore, QtWidgets, QtGui
from PyQt6.QtWidgets import QApplication, QMainWindow, QHeaderView, QTableWidgetItem, QTreeWidgetItem
from PyQt6.QtCore import QThread, pyqtSignal, QThreadPool
from util.HexView import HexView
import time

raw_dict = dict()


class Capture(QThread):
    signal = pyqtSignal(Packet)

    def __init__(self):
        super(Capture, self).__init__()
        self.cap = None

    def run(self):
        self.cap = pyshark.LiveCapture(interface="WLAN", use_json=True, include_raw=True, display_filter="ip"
                                       , output_file="./out.pcap")
        self.cap.apply_on_packets(self.send_signal, timeout=300)

    def stop(self):
        # self.quit()
        self.terminate()
        self.wait()

    def send_signal(self, pkt: Packet):
        # print("I'm not terminated")
        self.signal.emit(pkt)

# class SaveDict(QThread):



class Window(QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        self.pkt_dict = None
        self.ui = mainwindow.Ui_MainWindow()
        self.ui.setupUi(self)
        self.hex_view = HexView()
        self.hex_view.setParent(self.ui.splitter)
        self.ui.tableWidget.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table = self.ui.tableWidget
        self.tree = self.ui.treeWidget
        # self.text = self.ui.textBrowser
        self.menu = self.ui.menu
        self.capture = Capture()
        self.capture.signal.connect(self.deal_with_pkt)
        self.table_init()
        self.tree_init()
        self.ui.actionstart.triggered.connect(self.start)
        self.ui.actionstop.triggered.connect(self.stop)
        self.ui.actionstop.setEnabled(False)
        # self.ui.actionstop.setEnabled(False)
        self.is_running = False
        self.time = None

    def table_init(self):
        self.table.setRowCount(0)
        self.table.cellClicked.connect(self.show_detail)

    def tree_init(self):
        self.tree.setColumnCount(1)
        self.tree.setHeaderHidden(True)

    def start(self):
        self.tree.clear()
        if self.pkt_dict:
            del self.pkt_dict
        self.pkt_dict = dict()
        self.table.setRowCount(0)
        self.capture.start()
        self.time = time.time()
        self.is_running = True
        self.ui.actionstart.setEnabled(False)
        self.ui.actionstop.setEnabled(True)

    def stop(self):
        # print()
        self.capture.stop()
        self.is_running = False
        # print(self.capture.isRunning())
        self.ui.actionstart.setEnabled(True)
        self.ui.actionstop.setEnabled(False)

    def add_row(self, ls: list):
        row_cnt = self.table.rowCount()
        tmp = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.insertRow(row_cnt)
        for idx, item in enumerate(ls):
            self.table.setItem(row_cnt, idx, QTableWidgetItem(str(item)))
        self.table.setSortingEnabled(tmp)

    def deal_with_pkt(self, pkt: Packet):
        # print(pkt)
        # print(pkt)
        self.pkt_dict[pkt.number] = pkt
        self.add_row(
            [pkt.number, "{:.6f}".format(float(pkt.sniff_timestamp) - self.time), pkt.ip.src, pkt.ip.dst,
             pkt.highest_layer, pkt.length, pkt.frame_info])

    def show_detail(self, row, column):
        item = self.table.item(row, 0)
        # print(item.text())
        pkt: Packet = self.pkt_dict.get(int(item.text()))
        pkt.pretty_print()
        # print(pkt)
        if not pkt:
            print("packet map error")
            return
        # c = pyshark.InMemCapture()
        # tmp_pkt = c.parse_packet(pkt.get_raw_packet())
        self.show_pkt_tree(pkt)
        self.hex_view.generateView(pkt.get_raw_packet())

    def show_pkt_tree(self, pkt: Packet):
        self.tree.clear()
        layers: list = pkt.layers
        for l in layers:
            if l.layer_name == l.DATA_LAYER:
                b = QTreeWidgetItem(self.tree)
                b.setText(0, "DATA")
                break
            b = QTreeWidgetItem(self.tree)
            b.setText(0, l.layer_name)
            for field_line in l._get_all_field_lines():
                field_line = field_line.strip()
                child = QTreeWidgetItem(b)
                child.setText(0, field_line)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec())
